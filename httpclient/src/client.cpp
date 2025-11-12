// MIT License

// Copyright (c) 2025 W.M.R Jap-A-Joe

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "client.hpp"
#include "ssl.hpp"
#include "pluginit.h"
#include <vector>
#include <regex>
#include <sstream>
#include <cstring>
#include <iostream>
#include <iomanip> // for std::hex and std::setw
#include <atomic>

namespace http
{
    static std::atomic<int> gCount = 0;

    static void write_error(const std::string &message) 
	{
		std::cerr << message << '\n';
    }

    static bool string_contains(const std::string &haystack, const std::string &needle) 
	{
        return haystack.find(needle) != std::string::npos;
    }

    static bool string_ends_with(const std::string &haystack, const std::string &needle) 
	{
        if (haystack.length() >= needle.length()) 
            return (0 == haystack.compare(haystack.length() - needle.length(), needle.length(), needle));
        return false;
    }

    static std::string string_trim_start(const std::string& str) 
    {
        size_t start = 0;

        // Find the first non-whitespace character
        while (start < str.length() && std::isspace(static_cast<unsigned char>(str[start]))) 
        {
            ++start;
        }

        // Return the substring from the first non-whitespace character to the end
        return str.substr(start);
    }

    static std::vector<std::string> string_split(const std::string& str, char separator, size_t maxParts = 0) 
    {
        std::vector<std::string> result;
        size_t start = 0;
        size_t end = 0;

        while ((end = str.find(separator, start)) != std::string::npos) 
        {
            result.push_back(str.substr(start, end - start));
            start = end + 1;

            if (maxParts > 0 && result.size() >= maxParts - 1) 
                break; // Stop if we have reached maximum parts
        }
        result.push_back(str.substr(start)); // Add the last part
        return result;
    }
    
	static bool try_parse_uint16(const std::string &value, uint16_t &v)
	{
        std::stringstream ss(value);
        ss >> v;

        if (ss.fail() || !ss.eof())
            return false;
        
        return true;
	}

    static bool try_parse_int32(const std::string &value, int32_t &v)
    {
        std::stringstream ss(value);
        ss >> v;

        if (ss.fail() || !ss.eof())
            return false;
        
        return true;
    }

    static bool try_parse_uint64(const std::string &value, uint64_t &v)
    {
        std::stringstream ss(value);
        ss >> v;

        if (ss.fail() || !ss.eof())
            return false;
        
        return true;
    }

    static bool uri_get_scheme(const std::string &uri, std::string &value) 
	{
        std::regex schemeRegex(R"(([^:/?#]+):\/\/)");
        std::smatch match;
        if (std::regex_search(uri, match, schemeRegex)) 
		{
            value = match[1];
            return true;
        }
        return false;
    }

    static bool uri_get_host(const std::string &uri, std::string &value) 
	{
        std::regex hostRegex(R"(:\/\/([^/?#]+))");
        std::smatch match;
        if (std::regex_search(uri, match, hostRegex)) 
		{
            value = match[1];
            return true;
        }
        return false;
    }


    static bool uri_get_path(const std::string &uri, std::string &value) 
	{
        std::regex pathRegex(R"(:\/\/[^/?#]+([^?#]*))");
        std::smatch match;
        if (std::regex_search(uri, match, pathRegex)) 
		{
            value = match[1];
            return true;
        }
        return false;
    }

    static bool resolve(const std::string &uri, std::string &ip, uint16_t &port, std::string &hostname) 
	{
        std::string scheme, host, path;

        if(!uri_get_scheme(uri, scheme)) 
		{
            write_error("Failed to get scheme from URI");
            return false;
        }

        if(!uri_get_host(uri, host)) 
		{
            write_error("Failed to get host from URI");
            return false;
        }


        if(!uri_get_path(uri, path)) 
		{
            write_error("Failed to get path from URI");
            return false;
        }        

        if(string_contains(host, ":")) 
		{
            auto parts = string_split(host, ':');

            if(parts.size() != 2)
                return false;
            
            //Get rid of the :port part in the host
            host = parts[0];

            if(!try_parse_uint16(parts[1], port))
                return false;
            
        } 
		else 
		{
            if(scheme == "https")
                port = 443;
            else if(scheme == "http") 
                port = 80;
			else 
                return false;
        }

        // Resolve the hostname to an IP address
        struct addrinfo hints, *res;
        std::memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC; // IPv4 or IPv6
        hints.ai_socktype = SOCK_STREAM; // TCP

        int status = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res);

        if (status != 0) 
		{
			std::string error = "getaddrinfo error: " + std::string(gai_strerror(status));
            write_error(error);
            return false;
        }

        hostname = host;

        for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) 
		{
            void* addr;

            // Get the pointer to the address itself
            if (p->ai_family == AF_INET) 
			{ // IPv4
                struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
                addr = &(ipv4->sin_addr);
            } 
			else 
			{ // IPv6
                struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
                addr = &(ipv6->sin6_addr);
            }

            // Convert the IP to a string
            char ipstr[INET6_ADDRSTRLEN];
            inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
            ip = ipstr;
        }

        freeaddrinfo(res);
        return true;
    }

    static ip_version detect_ip_version(const std::string &ip) 
	{
        struct sockaddr_in sa;
        struct sockaddr_in6 sa6;

        if (inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) == 1) 
            return ip_version_ip_v4;

        if (inet_pton(AF_INET6, ip.c_str(), &(sa6.sin6_addr)) == 1)
            return ip_version_ip_v6;

        return ip_version_invalid;
    }

	client::client()
	{
        validateCertificate = true;
    #ifdef _WIN32
        if(gCount.load() == 0)
        {
            WSADATA wsaData;
            if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) 
            {
                write_error("Failed to initialize winsock");
            }
        }
    #endif

        if(gCount.load() == 0)
        {
            //"libssl.so"
        #ifdef _WIN32
            const char *curlPath = "libssl.dll";
        #else
            char *curlPath = pli_find_library_path("libssl.so");            
        #endif
            if(curlPath)
            {
                if(ssl::load_library(curlPath))
                {
                }
            #ifndef _WIN32
                pli_free_library_path(curlPath);
            #endif
            }
        }

        if(ssl::is_loaded())
        {
            sslContext = ssl::SSL_CTX_new(ssl::TLS_method());
        }
        else
        {
            sslContext = nullptr;
        }

        gCount.store(gCount.load() + 1);
	}

	client::~client()
	{
    #ifdef _WIN32
        if(gCount.load() == 1)
        {
            WSACleanup();
        }
    #endif

        if(sslContext)
        {
            ssl::SSL_CTX_free(sslContext);
            sslContext = nullptr;
        }

        if(gCount.load() == 1)
        {
            ssl::close_library();
        }

        gCount.store(gCount.load() - 1);
	}

    void client::set_validate_certificate(bool validate)
    {
        validateCertificate = validate;
        if(sslContext)
        {
            if(validate)
                ssl::SSL_CTX_set_verify(sslContext, SSL_VERIFY_PEER, nullptr);
            else
                ssl::SSL_CTX_set_verify(sslContext, SSL_VERIFY_NONE, nullptr);
        }
    }

    bool client::validate_certificate() const
    {
        return validateCertificate;
    }
    
    bool client::get(const request &req, response &res)
    {
        if(!sslContext)
        {
            write_error("client::get: failed to make request because SSL context is not initialized");
            return false;
        }

		connection_t connection = {0};
        connection.sslContext = sslContext;
        std::string path;
        std::string hostName;

        if(!connect(&connection, req.get_url(), path, hostName))
            return false;

		std::string requestHeader;

    	requestHeader += "GET " + path + " HTTP/1.1\r\n";
    	requestHeader += "Host: " + hostName + "\r\n";
    	requestHeader += "Accept: */*\r\n";

        auto requestHeaders = req.get_headers();

		if(requestHeaders.size() > 0)
		{
			for(const auto &h : requestHeaders)
			{
				requestHeader += h.first + ": " + h.second + "\r\n";
			}
		}

    	requestHeader += "Connection: close\r\n\r\n";

        // Send the request header
        if(!write_all_bytes(&connection, requestHeader.data(), requestHeader.size()))
        {
            close(&connection);
            return false;
        }

        std::string responseHeader;

        // Read the response header
        if(read_header(&connection, responseHeader) != header_error_none)
        {
            close(&connection);
            return false;
        }

        // Parse the response header
        if(!parse_header(responseHeader, res.header, res.statusCode, res.contentLength))
        {
            close(&connection);
            return false;
        }

		int64_t bytesReceived = 0;
		unsigned char buffer[1024];
		std::memset(buffer, 0, 1024);
        std::string body;

        // Read the body
		while ((bytesReceived = read(&connection, buffer, 1024)) > 0) 
		{
            if(onResponse)
                onResponse(buffer, bytesReceived);
		}

		close(&connection);

		return true;
    }

    bool client::post(const request &req, response &res)
    {
        if(!sslContext)
        {
            write_error("client::post: failed to make request because SSL context is not initialized");
            return false;
        }

		connection_t s = {0};
        s.sslContext = sslContext;
        std::string path;
        std::string hostName;

        if(!connect(&s, req.get_url(), path, hostName))
            return false;

        if(string_ends_with(path, "/"))
            path.pop_back();

		std::string requestHeader;

        requestHeader += "POST " + path + " HTTP/1.1\r\n";
        requestHeader += "Host: " + hostName + "\r\n";
        requestHeader += "Accept: */*\r\n";

        auto requestHeaders = req.get_headers();

		if(requestHeaders.size() > 0)
		{
			for(const auto &h : requestHeaders)
			{
				requestHeader += h.first + ": " + h.second + "\r\n";
			}
		}

        const uint8_t *pContent = req.get_content();
        const size_t contentLength = req.get_content_length();

        if(pContent && contentLength > 0)
        {
		    requestHeader += "Content-Type: " + req.get_content_type() + "\r\n";
            requestHeader += "Content-Length: " + std::to_string(contentLength) + "\r\n";
        }

        requestHeader += "Connection: close\r\n\r\n";

        // Send the request header
        if(!write_all_bytes(&s, requestHeader.data(), requestHeader.size()))
        {
            close(&s);
            return false;
        }

        // Send the content
        if(pContent && contentLength > 0)
        {
            if(!write_all_bytes(&s, pContent, contentLength))
            {
                close(&s);
                return false;
            }
        }

        std::string responseHeader;
        
        // Read the response header
        if(read_header(&s, responseHeader) != header_error_none)
        {
            close(&s);
            return false;
        }

        // Parse the response header
        if(!parse_header(responseHeader, res.header, res.statusCode, res.contentLength))
        {
            close(&s);
            return false;
        }

		int64_t bytesReceived = 0;
		unsigned char buffer[1024];
		std::memset(buffer, 0, 1024);

        // Read the body
		while ((bytesReceived = read(&s, buffer, 1024)) > 0) 
		{
            if(onResponse)
                onResponse(buffer, bytesReceived);
		}

		close(&s);

		return true;
    }

    bool client::connect(connection_t *connection, const std::string &url, std::string &path, std::string &hostName)
    {
        std::string URL = url;

        if(!string_ends_with(URL, "/"))
            URL += "/";

        std::string scheme;

        if(!uri_get_scheme(URL, scheme)) 
		{
            write_error("client::connect: failed to determine scheme from URI " + URL);
            return false;
        }

        if(!uri_get_path(URL, path)) 
		{
            write_error("client::connect: failed to determine path from URI " + URL);
            return false;
        }

        std::string ip;
        uint16_t port;
        
        if(!resolve(URL, ip, port, hostName)) 
        {
            write_error("client::connect: failed to resolve IP from URI " + URL);
            return false;
        }

        ip_version ipVersion = detect_ip_version(ip);

        if(ipVersion == ip_version_invalid) 
		{
            write_error("client::connect: invalid IP version");
            return false;
        }
        
        address_family addressFamily = (ipVersion == ip_version_ip_v4) ? address_family_af_inet : address_family_af_inet6;

        connection->s.fd = socket(static_cast<int>(addressFamily), SOCK_STREAM, 0);

        if(connection->s.fd < 0) 
		{
            write_error("client::connect: failed to create socket");
            return false;
        }

        int connectionResult = 0;

        connection->s.addressFamily = addressFamily;

        const int noDelayFlag = 1;
        set_socket_option(connection, IPPROTO_TCP, TCP_NODELAY, &noDelayFlag, sizeof(int));

        if(ipVersion == ip_version_ip_v4) 
		{
            connection->s.address.ipv4.sin_family = AF_INET;
            connection->s.address.ipv4.sin_port = htons(port);
            inet_pton(AF_INET, ip.c_str(), &connection->s.address.ipv4.sin_addr);
            connectionResult = ::connect(connection->s.fd, (struct sockaddr*)&connection->s.address.ipv4, sizeof(connection->s.address.ipv4));
        } 
		else 
		{
            connection->s.address.ipv6.sin6_family = AF_INET6;
            connection->s.address.ipv6.sin6_port = htons(port);
            inet_pton(AF_INET6, ip.c_str(), &connection->s.address.ipv6.sin6_addr);
            connectionResult = ::connect(connection->s.fd, (struct sockaddr*)&connection->s.address.ipv6, sizeof(connection->s.address.ipv6));
        }

        if(connectionResult < 0) 
		{
            write_error("client::connect: failed to connect");
            close(connection);
            return false;
        }

        bool secure = scheme == "https" ? true : false;

        if(secure)
        {
            connection->ssl = ssl::SSL_new(connection->sslContext);
            
            ssl::SSL_set_fd(connection->ssl, connection->s.fd);            
            ssl::SSL_ctrl(connection->ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, (void*)hostName.c_str());

            if (ssl::SSL_connect(connection->ssl) != 1) 
            {
                write_error("client::client: failed to SSL connect");
                close(connection);
                return false;
            }
        }

        return true;
    }

	void client::close(connection_t *connection)
	{
        if(connection->s.fd >= 0) 
		{
            auto emptyBuffers = [&] () {
                uint8_t buffer[1024];
                while(true) {
                    int64_t n = read(connection, buffer, 1024);
                    if(n <= 0)
                        break;
                }
            };

        #ifdef _WIN32
            ::shutdown(connection->s.fd, SD_SEND);
            emptyBuffers();
            closesocket(connection->s.fd);
        #else
            ::shutdown(connection->s.fd, SHUT_WR);
            emptyBuffers();
            ::close(connection->s.fd);
        #endif
            connection->s.fd = -1;
        }
        
        if(connection->ssl)
        {
            ssl::SSL_shutdown(connection->ssl);
            ssl::SSL_free(connection->ssl);
            connection->ssl = nullptr;
        }
	}

    int64_t client::read(connection_t *connection, void *buffer, size_t size) 
	{
        int64_t n = 0;
        if(connection->ssl)
        {
            n = ssl::SSL_read(connection->ssl, buffer, size);
        }
        else
        {
        #ifdef _WIN32
            n = ::recv(connection->s.fd, (char*)buffer, size, 0);
        #else
            n = ::recv(connection->s.fd, buffer, size, 0);
        #endif
        }
        return n;
    }

    int64_t client::peek(connection_t *connection, void *buffer, size_t size) 
	{
        int64_t n = 0;
        if(connection->ssl)
        {
            n = ssl::SSL_peek(connection->ssl, buffer, size);
        }
        else
        {
        #ifdef _WIN32
            n = ::recv(connection->s.fd, (char*)buffer, size, MSG_PEEK);
        #else
            n = ::recv(connection->s.fd, buffer, size, MSG_PEEK);
        #endif
        }
        return n;
    }

    int64_t client::write(connection_t *connection, const void *buffer, size_t size)
	{
        int64_t n = 0;
        if(connection->ssl)
        {
            n = ssl::SSL_write(connection->ssl, buffer, size);
        }
        else
        {
        #ifdef _WIN32
            n = ::send(connection->s.fd, (char*)buffer, size, 0);
        #else
            n = ::send(connection->s.fd, buffer, size, 0);
        #endif
        }
        return n;
    }

    bool client::write_all_bytes(connection_t *connection, const void *buffer, size_t size)
    {
        const uint8_t *ptr = static_cast<const uint8_t*>(buffer);
        size_t totalSent = 0;

        while (totalSent < size) 
        {
            int64_t bytesSent = write(connection, ptr + totalSent, size - totalSent);
            
            if (bytesSent < 0) 
            {
                // An error occurred
                return false;
            } 
            else if (bytesSent == 0) 
            {
                // Connection closed
                return false;
            }

            totalSent += bytesSent;
        }

        return true; // All bytes sent successfully
    }

    bool client::set_socket_option(connection_t *connection, int level, int option, const void *value, uint32_t valueSize)
    {
    #ifdef _WIN32
        return setsockopt(connection->s.fd, level, option, (char*)value, valueSize) != 0 ? false : true;
    #else
        return setsockopt(connection->s.fd, level, option, value, valueSize) != 0 ? false : true;
    #endif
    }

    header_error client::read_header(connection_t *connection, std::string &header)
    {
        if(!connection)
            return header_error_failed_to_read;

        const size_t maxHeaderSize = 16384;
        const size_t bufferSize = maxHeaderSize;
        std::vector<char> buffer;
        buffer.resize(bufferSize);
        int64_t headerEnd = 0;
        int64_t totalHeaderSize = 0;
        bool endFound = false;

        auto find_header_end = [] (const char* haystack, const char* needle, size_t haystackLength, size_t needleLength) -> int64_t {
            for (size_t i = 0; i <= haystackLength - needleLength; ++i) {
                if (memcmp(haystack + i, needle, needleLength) == 0) {
                    return static_cast<int>(i); // Found the needle, return the index
                }
            }
            return -1; // Not found
        };


        char *pBuffer = buffer.data();

        // Peek to find the end of the header
        while (true) 
        {
            int64_t bytesPeeked = peek(connection, pBuffer, bufferSize);

            if (bytesPeeked < 0)
                return header_error_failed_to_peek;

            totalHeaderSize += bytesPeeked;

            if(totalHeaderSize > maxHeaderSize) 
            {
                printf("header_error_max_size_exceeded 1, %zu/%zu\n", totalHeaderSize, maxHeaderSize);
                return header_error_max_size_exceeded;
            }

            //Don't loop indefinitely...
            if(bytesPeeked == 0)
                break;
            
            // Look for the end of the header (double CRLF)
            //int64_t end = find_header_end(pBuffer, bytesPeeked);
            int64_t end = find_header_end(pBuffer, "\r\n\r\n", bytesPeeked, 4);

            if(end >= 0)
            {
                headerEnd = end + 4; //Include the length of the CRLF
                endFound = true;
                break;                
            }

            // const char* endOfHeader = std::search(pBuffer, pBuffer + bytesPeeked, "\r\n\r\n", "\r\n\r\n" + 4);
            // if (endOfHeader != pBuffer + bytesPeeked) 
            // {
            //     headerEnd = endOfHeader - pBuffer + 4; // Include the length of the CRLF
            //     endFound = true;
            //     break;
            // }
        }

        if(!endFound)
            return header_error_end_not_found;

        // Now read the header
        header.resize(headerEnd);
        int64_t bytesRead = read(connection, header.data(), headerEnd);
        if (bytesRead < 0) 
            return header_error_failed_to_read;

        if(header.size() > maxHeaderSize) 
        {
            printf("header_error_max_size_exceeded 2, %zu/%zu\n", header.size(), maxHeaderSize);
            return header_error_max_size_exceeded;
        }

        return header_error_none;
    }

    bool client::parse_header(const std::string &responseText, headers &header, int &statusCode, uint64_t &contentLength)
    {
        std::istringstream responseStream(responseText);
        std::string line;
        size_t count = 0;

        auto to_lower = [] (const std::string &str) -> std::string {
            std::string lower_str = str;
            std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(),
                        [](unsigned char c) { return std::tolower(c); });
            return lower_str;
        };

        while(std::getline(responseStream, line))
        {
            line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());

            if(line.size() == 0)
                continue;

            if(count == 0)
            {
                if(line[line.size() - 1] == ' ')
                    line.pop_back();

                auto parts = string_split(line, ' ', 0);
                
                if(parts.size() < 2)
                    return false;

                if(!try_parse_int32(parts[1], statusCode))
                    return false;
            }
            else
            {
                auto parts = string_split(line, ':', 2);

                if(parts.size() == 2)
                {
                    parts[0] = to_lower(parts[0]);
                    parts[1] = string_trim_start(parts[1]);
                    header[parts[0]] = parts[1];
                }
            }

            count++;
        }

        if(header.contains("content-length"))
        {
            if(!try_parse_uint64(header["content-length"], contentLength))
                contentLength = 0;
        }

        return count > 0;
    }

    size_t client::write_callback(void* contents, size_t size, size_t nmemb, void* userp)
    {
        client *pClient = reinterpret_cast<client*>(userp);
        size_t totalSize = size * nmemb;
        if(pClient->onResponse)
            pClient->onResponse(contents, totalSize);

        // std::string* str = static_cast<std::string*>(userp);
        // str->append(static_cast<char*>(contents), totalSize);
        return totalSize;
    }
    
    size_t client::header_callback(void* contents, size_t size, size_t nmemb, void* userp)
    {
        size_t totalSize = size * nmemb;
        std::string* str = static_cast<std::string*>(userp);
        str->append(static_cast<char*>(contents), totalSize);
        return totalSize;
    }

    request::request()
    {
        content = nullptr;
        contentLength = 0;
        contentType = "text/plain";
        ownsData = false;
    }

    request::~request()
    {
        if(content && ownsData)
        {
            delete[] content;
        }
    }

    void request::set_url(const std::string &url)
    {
        this->url = url;
    }

    std::string request::get_url() const
    {   
        return url;
    }

    void request::set_content(void *data, size_t size, bool copyData)
    {
        if(!data || size == 0)
            return;

        if(content && ownsData)
        {
            delete[] content;
            content = nullptr;
            contentLength = 0;
        }

        ownsData = copyData;
        contentLength = size;

        if(ownsData)
        {
            content = new uint8_t[size];
            std::memcpy(content, data, size);
        }
        else
        {
            content = reinterpret_cast<uint8_t*>(data);
            contentLength = size;
        }

        return;
    }

    uint8_t *request::get_content() const
    {
        return content;
    }

    size_t request::get_content_length() const
    {
        return contentLength;
    }

    void request::set_content_type(const std::string &contentType)
    {
        this->contentType = contentType;
    }

    std::string request::get_content_type() const
    {
        return contentType;
    }

    void request::set_header(const std::string &key, const std::string &value)
    {
        header[key] = value;
    }

    headers request::get_headers() const
    {
        return header;
    }

    response::response()
    {
        statusCode = 0;
        contentLength = 0;
    }

    int response::get_status_code() const
    {
        return statusCode;
    }
    
    size_t response::get_content_length() const
    {
        return contentLength;
    }

    headers &response::get_headers()
    {
        return header;
    }
}