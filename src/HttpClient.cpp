#include "HttpClient.hpp"
#include "Platform.hpp"
#include "openssl.hpp"
#include "zlib.hpp"
#include <utility>
#include <atomic>
#include <cassert>
#include <filesystem>
#include <iostream>
#include <cstring>
#include <algorithm>

#if defined(HTTP_PLATFORM_WINDOWS)
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#if defined(HTTP_PLATFORM_UNIX)
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/wait.h>
#endif

namespace Http
{
    // ███████╗ ██████╗  ██████╗██╗  ██╗███████╗████████╗
    // ██╔════╝██╔═══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝
    // ███████╗██║   ██║██║     █████╔╝ █████╗     ██║
    // ╚════██║██║   ██║██║     ██╔═██╗ ██╔══╝     ██║
    // ███████║╚██████╔╝╚██████╗██║  ██╗███████╗   ██║
    // ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝

#if defined(HTTP_PLATFORM_WINDOWS)
#define INVALID_SOCKET_HANDLE INVALID_SOCKET
#define SOCKET_ERROR WSAGetLastError()
#define SOCKET_EWOULDBLOCK WSAEWOULDBLOCK
#define SOCKET_EGAIN WSAEWOULDBLOCK // Windows doesn't really have EAGAIN
#else
#define INVALID_SOCKET_HANDLE -1
#define SOCKET_ERROR errno
#define SOCKET_EWOULDBLOCK EWOULDBLOCK
#define SOCKET_EGAIN EAGAIN
#endif

    static std::atomic<bool> gWinsockInitialized = false;

    Socket::Socket()
    {
        descriptor = INVALID_SOCKET_HANDLE;
#if defined(HTTP_PLATFORM_WINDOWS)
        if (!gWinsockInitialized.load())
        {
            WSADATA wsaData;
            int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
            assert(result != 0 && "Failed to initialize winsock");
            if(result == 0)
                gWinsockInitialized.store(true);
        }
#endif
    }

    Socket::~Socket()
    {
        Close();
    }

    Socket::Socket(const Socket &other)
    {
        descriptor = other.descriptor;
    }

    Socket::Socket(Socket &&other) noexcept
    {
        descriptor = std::exchange(other.descriptor, INVALID_SOCKET_HANDLE);
    }

    Socket &Socket::operator=(const Socket &other)
    {
        if (this != &other)
        {
            descriptor = other.descriptor;
        }
        return *this;
    }

    Socket &Socket::operator=(Socket &&other) noexcept
    {
        if (this != &other)
        {
            descriptor = std::exchange(other.descriptor, INVALID_SOCKET_HANDLE);
        }
        return *this;
    }

    bool Socket::Connect(const std::string &ip, uint16_t port)
    {
        if (descriptor != INVALID_SOCKET_HANDLE) // Expands to -1
        {
            printf("Invalid socket state 1\n");
            return false;
        }

        auto getAddressFamily = [ip]() -> int
        {
            struct sockaddr_in sa;
            if (inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) == 1)
                return AF_INET;

            struct sockaddr_in6 sa6;
            if (inet_pton(AF_INET6, ip.c_str(), &(sa6.sin6_addr)) == 1)
                return AF_INET6;
            return -1;
        };

        int addressFamily = getAddressFamily();

        if (addressFamily == -1)
        {
            printf("Address family error\n");
            return false;
        }

        descriptor = ::socket(addressFamily, SOCK_STREAM, 0);

        if (descriptor == INVALID_SOCKET_HANDLE)
        {
            printf("Invalid socket state 2\n");
            return false;
        }

        int connectionResult = -1;

        if (addressFamily == AF_INET)
        {
            struct sockaddr_in address = {0};
            address.sin_family = AF_INET;
            address.sin_port = htons(port);
            inet_pton(AF_INET, ip.c_str(), &address.sin_addr);
            connectionResult = ::connect(descriptor, (struct sockaddr *)&address, sizeof(address));
        }
        else
        {
            sockaddr_in6 address = {0};
            address.sin6_family = AF_INET6;
            address.sin6_port = htons(port);
            inet_pton(AF_INET6, ip.c_str(), &address.sin6_addr);
            connectionResult = ::connect(descriptor, (struct sockaddr *)&address, sizeof(address));
        }

        if (connectionResult < 0)
        {
            printf("Connection result: %d\n", connectionResult);
            Close();
            return false;
        }

        return true;
    }

    void Socket::Close()
    {
        if (descriptor != INVALID_SOCKET_HANDLE)
        {
#if defined(HTTP_PLATFORM_WINDOWS)
            closesocket(descriptor);
#elif defined(HTTP_PLATFORM_UNIX)
            ::close(descriptor);
#endif
        }
        descriptor = INVALID_SOCKET_HANDLE;
    }

    void Socket::Shutdown()
    {
#if defined(HTTP_PLATFORM_WINDOWS)
        ::shutdown(descriptor, SD_SEND);
#elif defined(HTTP_PLATFORM_UNIX)
        ::shutdown(descriptor, SHUT_WR);
#endif
    }

    int64_t Socket::Read(void *buffer, uint64_t size)
    {
#if defined(HTTP_PLATFORM_WINDOWS)
        return ::recv(descriptor, (char *)buffer, size, 0);
#elif defined(HTTP_PLATFORM_UNIX)
        return ::recv(descriptor, buffer, size, 0);
#endif
        return 0;
    }

    int64_t Socket::Write(const void *buffer, uint64_t size)
    {
#if defined(HTTP_PLATFORM_WINDOWS)
        return ::send(descriptor, (char *)buffer, size, 0);
#elif defined(HTTP_PLATFORM_UNIX)
        return ::send(descriptor, buffer, size, 0);
#endif
        return 0;
    }
    
    int64_t Socket::Peek(void *buffer, uint64_t size)
    {
#if defined(HTTP_PLATFORM_WINDOWS)
		return ::recv(descriptor, (char*)buffer, size, MSG_PEEK);
#elif defined(HTTP_PLATFORM_UNIX)
		return ::recv(descriptor, buffer, size, MSG_PEEK);
#endif
    }

    int32_t Socket::GetDescriptor() const
    {
        return descriptor;
    }

    // ███████╗████████╗██████╗ ███████╗ █████╗ ███╗   ███╗
    // ██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔══██╗████╗ ████║
    // ███████╗   ██║   ██████╔╝█████╗  ███████║██╔████╔██║
    // ╚════██║   ██║   ██╔══██╗██╔══╝  ██╔══██║██║╚██╔╝██║
    // ███████║   ██║   ██║  ██║███████╗██║  ██║██║ ╚═╝ ██║
    // ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝

    MemoryStream::MemoryStream(void *memory, size_t size, bool copyMemory)
    {
        if (memory == nullptr)
            throw std::runtime_error("Memory can not be null");

        if (size == 0)
            throw std::runtime_error("Size can not be 0");

        this->copyMemory = copyMemory;
        this->size = size;
        length = size;

        if (!copyMemory)
        {
            this->memory = memory;
        }
        else
        {
            this->memory = std::malloc(size);
            std::memcpy(this->memory, memory, size);
        }
    }

    MemoryStream::~MemoryStream()
    {
        if (copyMemory)
        {
            if (memory != nullptr)
            {
                std::free(memory);
            }
        }

        memory = nullptr;
    }

    int64_t MemoryStream::Read(void *buffer, size_t bytesToRead)
    {
        if (!memory || !buffer)
            return 0;

        size_t available = (readPosition < (int64_t)size)
                               ? size - readPosition
                               : 0;

        size_t toRead = (bytesToRead <= available) ? bytesToRead : available;

        std::memcpy(buffer, static_cast<uint8_t *>(memory) + readPosition, toRead);

        readPosition += toRead;
        return static_cast<int64_t>(toRead);
    }

    int64_t MemoryStream::Write(const void *buffer, size_t bytesToWrite)
    {
        if (!memory || !buffer)
            return 0;

        size_t available = (writePosition < (int64_t)size)
                               ? size - writePosition
                               : 0;

        size_t toWrite = (bytesToWrite <= available) ? bytesToWrite : available;

        std::memcpy(static_cast<uint8_t *>(memory) + writePosition, buffer, toWrite);

        writePosition += toWrite;
        return static_cast<int64_t>(toWrite);
    }

    int64_t MemoryStream::Seek(int64_t offset, SeekOrigin origin)
    {
        int64_t newPos = 0;

        switch (origin)
        {
        case SeekOrigin::Begin:
            newPos = offset;
            break;

        case SeekOrigin::Current:
            newPos = readPosition + offset; // use readPosition as unified cursor
            break;

        case SeekOrigin::End:
            newPos = static_cast<int64_t>(size) + offset;
            break;

        default:
            throw std::invalid_argument("Invalid seek origin");
        }

        if (newPos < 0)
            newPos = 0;
        if (newPos > (int64_t)size)
            newPos = size;

        // Sync both read and write cursors
        readPosition = writePosition = newPos;

        return newPos;
    }

    int64_t MemoryStream::GetReadOffset()
    {
        return readPosition;
    }

    static std::ios_base::openmode AccessToOpenMode(FileAccess access)
    {
        // Prevents Windows line-ending translation
        const std::ios_base::openmode mode = std::ios::binary;

        switch (access)
        {
        case FileAccess::Read:
            return mode | std::ios::in;
        case FileAccess::Write:
            return mode | std::ios::out | std::ios::trunc; // Truncate the file if it exists
        case FileAccess::ReadWrite:
            return mode | std::ios::in | std::ios::out;
        default:
            throw std::invalid_argument("Invalid file access type");
        }
    }

    FileStream::FileStream(const std::string &filePath, FileAccess access)
    {
        this->access = access;
        std::ios_base::openmode mode = AccessToOpenMode(access);
        file.open(filePath, mode);

        if (!file)
            throw std::runtime_error("Failed to open file: " + filePath);

        std::streampos currentPos = file.tellg();
        file.seekg(0, std::ios::end);
        length = static_cast<int64_t>(file.tellg());
        file.seekg(currentPos);
    }

    int64_t FileStream::Read(void *buffer, size_t size)
    {
        if (!(access == FileAccess::Read || access == FileAccess::ReadWrite))
            throw std::runtime_error("File not opened in read mode");

        file.read(reinterpret_cast<char *>(buffer), size);
        int64_t bytesRead = file.gcount();
        readPosition += bytesRead;
        return bytesRead;
    }

    int64_t FileStream::Write(const void *buffer, size_t size)
    {
        if (!(access == FileAccess::Write || access == FileAccess::ReadWrite))
            throw std::runtime_error("File not opened in write mode");

        file.write(reinterpret_cast<const char *>(buffer), size);
        if (!file)
            throw std::runtime_error("Failed to write to file");

        writePosition += size;
        return size;
    }

    int64_t FileStream::Seek(int64_t offset, SeekOrigin origin)
    {
        if (origin == SeekOrigin::Begin)
        {
            file.seekg(offset, std::ios::beg);
            file.seekp(offset, std::ios::beg);
        }
        else if (origin == SeekOrigin::Current)
        {
            file.seekg(offset, std::ios::cur);
            file.seekp(offset, std::ios::cur);
        }
        else if (origin == SeekOrigin::End)
        {
            file.seekg(offset, std::ios::end);
            file.seekp(offset, std::ios::end);
        }
        else
        {
            throw std::invalid_argument("Invalid seek origin");
        }

        if (!file)
            throw std::runtime_error("Seek operation failed");

        readPosition = file.tellg();
        writePosition = file.tellp();

        if (access == FileAccess::Read)
            return readPosition;
        else if (access == FileAccess::Write)
            return writePosition;
        else
            return readPosition;
    }

    int64_t FileStream::GetReadOffset()
    {
        return readPosition;
    }

    FileStream::~FileStream()
    {
        if (file.is_open())
            file.close();
    }

    ContentStream::ContentStream(std::shared_ptr<Socket> socket, SSL *ssl, void *initialContent, size_t initialContentLength, const std::vector<Encoding> &transferEncoding, const std::vector<Encoding> &contentEncoding)
    {
        this->socket = socket;
        this->ssl = ssl;

        if (!initialContent || initialContentLength == 0)
        {
            this->initialContent = nullptr;
            this->initialContentLength = 0;
            initialContentConsumed = 0;
        }
        else
        {
            this->initialContent = std::malloc(initialContentLength);
            this->initialContentLength = initialContentLength;

            std::memcpy(this->initialContent, initialContent, initialContentLength);

            initialContentConsumed = 0;
        }

        isChunked = false;
        isGzip = false;

        for (size_t i = 0; i < transferEncoding.size(); i++)
        {
            if(transferEncoding[i] == Encoding::Chunked)
            {
                isChunked = true;
            }
            if(transferEncoding[i] == Encoding::GZip)
            {
                isGzip = true;
            }
        }
        
        for (size_t i = 0; i < contentEncoding.size(); i++)
        {
            if(contentEncoding[i] == Encoding::Chunked)
            {
                isChunked = true;
            }
            if(contentEncoding[i] == Encoding::GZip)
            {
                isGzip = true;
            }
        }

        bytesRemainingInChunk = 0;
        firstChunk = true;
    }

    ContentStream::~ContentStream()
    {
        if (initialContent)
            std::free(initialContent);
        initialContent = nullptr;
        if (ssl)
        {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        ssl = nullptr;
        if (socket)
        {
            socket->Close();
        }

        if (decompressionStream)
        {
            inflateEnd(decompressionStream.get());
        }
    }

    int64_t ContentStream::ReadInternal(void *buffer, size_t size)
    {
        if (socket == nullptr)
            return 0;

        if (buffer == nullptr)
            return 0;

        if (size == 0)
            return 0;

        if (initialContentLength == 0)
        {
            if (ssl)
                return SSL_read(ssl, buffer, size);
            else
                return socket->Read(buffer, size);
        }

        if (initialContentConsumed < initialContentLength)
        {
            size_t remaining = initialContentLength - initialContentConsumed;
            size_t toConsume = (size < remaining) ? size : remaining;

            std::memcpy(buffer, (uint8_t *)initialContent + initialContentConsumed, toConsume);
            initialContentConsumed += toConsume;

            return static_cast<int64_t>(toConsume);
        }

        if (ssl)
            return SSL_read(ssl, buffer, size);
        else
            return socket->Read(buffer, size);
    }

    std::string ContentStream::ReadLineInternal()
    {
        std::string line;
        char c;
        const size_t maxLineLength = 4096; // Standard HTTP limit is usually 8KB

        while (ReadInternal(&c, 1) > 0)
        {
            line += c;

            // Check for line ending
            if (line.size() >= 2 && line.substr(line.size() - 2) == "\r\n")
            {
                return line.substr(0, line.size() - 2);
            }

            // Safety break
            if (line.size() > maxLineLength)
            {
                break; 
            }
        }
        return line;
    }

    int64_t ContentStream::ReadChunked(void* buffer, size_t size)
    {
        if (socket == nullptr || buffer == nullptr || size == 0)
        {
            return 0;
        }
            
        if (bytesRemainingInChunk == 0)
        {
            // If we just finished a chunk, we MUST consume the CRLF 
            // that follows the chunk data before reading the next size.
            if (!firstChunk)
            {
                ReadLineInternal(); 
            }

            std::string hexLine = ReadLineInternal(); 
            if (hexLine.empty())
            {
                return 0;
            }

            try 
            {
                size_t semiColon = hexLine.find(';');
                bytesRemainingInChunk = std::stoll(hexLine.substr(0, semiColon), nullptr, 16);
            }
            catch (...)
            {
                return -1; // Malformed chunk header
            }

            firstChunk = false;

            if (bytesRemainingInChunk == 0)
            {
                // Consume any trailers until we hit the final empty line
                std::string trailer;
                while (!(trailer = ReadLineInternal()).empty()) 
                {
                    // Optionally store trailers here if needed
                }
                return 0;
            }
        }

        size_t toRead = std::min(size, static_cast<size_t>(bytesRemainingInChunk));
        int64_t bytesRead = ReadInternal(buffer, toRead);

        if (bytesRead > 0)
        {
            bytesRemainingInChunk -= bytesRead;
        }

        return bytesRead;
    }

    int64_t ContentStream::ReadGZip(void* buffer, size_t size)
    {
        if (socket == nullptr)
            return 0;

        if (buffer == nullptr)
            return 0;

        if (size == 0)
            return 0;

        if(!decompressionStream)
        {
            internalBuffer.resize(8192);
            decompressionStream = std::make_unique<z_stream>();
            std::memset(decompressionStream.get(), 0 , sizeof(z_stream));

            // 16 + 15 (MAX_WBITS) = 31, which tells zlib to expect GZIP headers
            int status = inflateInit2(decompressionStream.get(), 31);

            if (status != 0) // Z_OK
            {
                decompressionStream.reset();
                decompressionStream = nullptr;
                return -1;
            }
        }

        decompressionStream->next_out = (Bytef*)buffer;
        decompressionStream->avail_out = (uInt)size;

        while (decompressionStream->avail_out > 0)
        {
            if (decompressionStream->avail_in == 0)
            {
                int64_t bytesRead = 0;

                if(isChunked)
                    bytesRead = ReadChunked(internalBuffer.data(), internalBuffer.size());
                else
                    bytesRead = ReadInternal(internalBuffer.data(), internalBuffer.size());

                if (bytesRead < 0)
                    return -1; // Underlying stream error
                
                if (bytesRead == 0)
                    break; // No more data available from the source

                decompressionStream->next_in = (Bytef*)internalBuffer.data();
                decompressionStream->avail_in = (uInt)bytesRead;
            }

            // This calls your 'inflate' function pointer
            int ret = inflate(decompressionStream.get(), 0); // Z_NO_FLUSH

            if (ret == 1) // Z_STREAM_END
            {
                break; 
            }

            if (ret != 0 && ret != -5) // Z_OK, Z_BUF_ERROR
            {
                return -1;
            }
        }

        return static_cast<int64_t>(size - decompressionStream->avail_out);
    }

    int64_t ContentStream::Read(void *buffer, size_t size)
    {
    // Layer 1: Content-Encoding (The "What")
        if (isGzip)
        {
            return ReadGZip(buffer, size);
        }

        // Layer 2: Transfer-Encoding (The "How")
        if (isChunked)
        {
            return ReadChunked(buffer, size);
        }

        // Layer 3: Raw Data (The "Source")
        return ReadInternal(buffer, size);
    }

    int64_t ContentStream::Write(const void *buffer, size_t size)
    {
        return 0;
    }

    int64_t ContentStream::Seek(int64_t offset, SeekOrigin origin)
    {
        return 0;
    }

    int64_t ContentStream::GetReadOffset()
    {
        return 0;
    }

    void ContentStream::Dispose()
    {
        if (initialContent)
            std::free(initialContent);
        initialContent = nullptr;
        if (ssl)
        {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        ssl = nullptr;

        if (socket)
        {
            socket->Close();
            socket.reset();
        }
    }

    // ██╗  ██╗████████╗████████╗██████╗  ██████╗██╗     ██╗███████╗███╗   ██╗████████╗
    // ██║  ██║╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║     ██║██╔════╝████╗  ██║╚══██╔══╝
    // ███████║   ██║      ██║   ██████╔╝██║     ██║     ██║█████╗  ██╔██╗ ██║   ██║
    // ██╔══██║   ██║      ██║   ██╔═══╝ ██║     ██║     ██║██╔══╝  ██║╚██╗██║   ██║
    // ██║  ██║   ██║      ██║   ██║     ╚██████╗███████╗██║███████╗██║ ╚████║   ██║
    // ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝      ╚═════╝╚══════╝╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝

    Request::Request(Method method, const std::string &url)
    {
        this->method = method;
        this->url = url;
        this->content = nullptr;
    }

    Method Request::GetMethod() const
    {
        return method;
    }

    std::string &Request::GetUrl()
    {
        return url;
    }

    std::unordered_map<std::string, std::string> &Request::GetHeaders()
    {
        return headers;
    }

    std::vector<std::string> &Request::Getcookies()
    {
        return cookies;
    }

    void Request::AddHeader(const std::string &key, const std::string &value)
    {
        headers[key] = value;
    }

    void Request::SetCookie(const std::string &cookie)
    {
        cookies.push_back(cookie);
    }

    void Request::SetContent(Stream *content, const std::string &contentType)
    {
        if (!content)
            return;
        this->content = content;
        this->contentType = contentType;
    }

    Response::Response()
    {
        this->status = StatusCode::Unknown;
        this->content = nullptr;
        this->contentLength = 0;
    }

    StatusCode Response::GetStatus() const
    {
        return status;
    }

    std::unordered_map<std::string, std::string> &Response::GetHeaders()
    {
        return headers;
    }

    std::vector<std::string> &Response::Getcookies()
    {
        return cookies;
    }

    ContentStream *Response::GetContent() const
    {
        return content.get();
    }

    bool Response::GetContentAsString(std::string &str)
    {
        if (!content)
            return false;

        if (GetContentLength() > 0)
        {
            uint64_t contentLength = GetContentLength();
            uint64_t bytesRead = 0;
            uint64_t totalBytesRead = 0;
            char buffer[1024] = {0};

            while (totalBytesRead < contentLength)
            {
                bytesRead = content->Read(buffer, 1024);

                if (bytesRead > 0)
                {
                    totalBytesRead += bytesRead;
                    str.append(buffer, bytesRead);
                }
                else
                {
                    if (SOCKET_ERROR == SOCKET_EGAIN || SOCKET_ERROR == SOCKET_EWOULDBLOCK)
                        continue;
                    return false;
                }
            }

            return true;
        }
        else
        {
            //Possibly chunked payload
            char buffer[1024] = {0};
            uint64_t bytesRead = 0;

            while ((bytesRead = content->Read(buffer, 1023)) > 0)
            {
                str.append(buffer, bytesRead);
            }

            return str.size() > 0;
        }

        return false;
    }

    uint64_t Response::GetContentLength() const
    {
        return contentLength;
    }

    void Response::Dispose()
    {
        if (!content)
            return;
        content->Dispose();
    }

    Client::Client()
    {
        if (SSL_library_load())
        {
            sslContext = SSL_CTX_new(TLS_method());
            std::cout << "libssl loaded\n";
        }
        else
        {
            sslContext = nullptr;
            std::cout << "Failed to load libssl\n";
        }

        if (zlib_load_library())
            std::cout << "libz loaded\n";
        else
            std::cout << "Failed to load libz\n";
    }

    Client::Client(Client &&other) noexcept
    {
        sslContext = std::exchange(other.sslContext, nullptr);
    }

    Client::~Client()
    {
        if (sslContext)
            SSL_CTX_free(sslContext);
        sslContext = nullptr;
    }

    Client &Client::operator=(Client &&other) noexcept
    {
        if (this != &other)
        {
            sslContext = std::exchange(other.sslContext, nullptr);
        }
        return *this;
    }

    bool Uri::TryParse(const std::string &uri, Uri &result)
    {
        if (uri.empty())
        {
            return false;
        }

        std::string remaining = uri;

        if (!remaining.empty() && remaining.back() == '/')
        {
            remaining.pop_back();
        }

        // 1. Extract Scheme
        size_t schemeEnd = remaining.find("://");
        if (schemeEnd == std::string::npos)
        {
            return false;
        }

        result.scheme = remaining.substr(0, schemeEnd);
        remaining = remaining.substr(schemeEnd + 3);

        // 2. Separate Authority (Host/IP) from Path/Query
        size_t pathStart = remaining.find('/');
        if (pathStart != std::string::npos)
        {
            result.host = remaining.substr(0, pathStart);
            result.pathAndQueuery = remaining.substr(pathStart);
        }
        else
        {
            result.host = remaining;
            result.pathAndQueuery = "/";
        }

        // 3. Isolate Hostname/IP from Port
        std::string service = result.scheme;
        std::string lookupNode = result.host;

        if (lookupNode.front() == '[')
        {
            // IPv6 Literal [addr]:port
            size_t closingBracket = lookupNode.find(']');
            if (closingBracket == std::string::npos)
            {
                return false;
            }

            std::string ipOnly = lookupNode.substr(1, closingBracket - 1);
            size_t portSeparator = lookupNode.find(':', closingBracket);

            if (portSeparator != std::string::npos)
            {
                service = lookupNode.substr(portSeparator + 1);
            }

            lookupNode = ipOnly;
        }
        else
        {
            // Hostname or IPv4 host:port
            size_t portSeparator = lookupNode.find(':');
            if (portSeparator != std::string::npos)
            {
                service = lookupNode.substr(portSeparator + 1);
                lookupNode = lookupNode.substr(0, portSeparator);
            }
        }

        // 4. Resolve via getaddrinfo
        struct addrinfo hints;
        struct addrinfo *addrResult = nullptr;

        std::memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(lookupNode.c_str(), service.c_str(), &hints, &addrResult) != 0)
        {
            return false;
        }

        // 5. Extract IP and Port
        char ipBuffer[INET6_ADDRSTRLEN];
        void *rawAddress = nullptr;

        if (addrResult->ai_family == AF_INET)
        {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)addrResult->ai_addr;
            rawAddress = &(ipv4->sin_addr);
            result.port = ntohs(ipv4->sin_port);
        }
        else
        {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)addrResult->ai_addr;
            rawAddress = &(ipv6->sin6_addr);
            result.port = ntohs(ipv6->sin6_port);
        }

        if (inet_ntop(addrResult->ai_family, rawAddress, ipBuffer, sizeof(ipBuffer)) != nullptr)
        {
            result.ip = std::string(ipBuffer);
        }

        result.host = lookupNode;

        if (result.port == 80 || result.port == 443)
            result.isDefaultPort = true;
        else
            result.isDefaultPort = false;

        freeaddrinfo(addrResult);
        return true;
    }

    std::string Uri::GetHost() const
    {
        return host;
    }

    std::string Uri::GetPathAndQueuery() const
    {
        return pathAndQueuery;
    }

    std::string Uri::GetScheme() const
    {
        return scheme;
    }

    std::string Uri::GetIP() const
    {
        return ip;
    }

    uint16_t Uri::GetPort() const
    {
        return port;
    }

    bool Uri::IsDefaultPort() const
    {
        return isDefaultPort;
    }

    std::shared_ptr<Response> Client::Send(const Request &request)
    {
        if (!sslContext)
            return std::make_shared<Response>();

        std::shared_ptr<Socket> socket = std::make_shared<Socket>();

        Uri uri;

        if (!Uri::TryParse(request.url, uri))
            return std::make_shared<Response>();

        std::string host = uri.GetHost();
        std::string hostHeader = uri.IsDefaultPort() ? uri.GetHost() : uri.GetHost() + ":" + std::to_string(uri.GetPort());
        std::string path = uri.GetPathAndQueuery();
        std::string ip = uri.GetIP();
        uint16_t port = uri.GetPort();

        if (!socket->Connect(ip, port))
        {
            std::cout << "Failed to connect\n";
            return std::make_shared<Response>();
        }

        SSL *ssl = nullptr;

        if (request.url.size() >= 5 && request.url.compare(0, 5, "https") == 0)
        {
            ssl = SSL_new(sslContext);

            SSL_set_fd(ssl, socket->GetDescriptor());
            SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, (void *)host.c_str());

            if (SSL_connect(ssl) != 1)
            {
                std::cout << "Failed to ssl connect\n";
                CloseConnection(socket.get(), ssl);
                return std::make_shared<Response>();
            }
        }

        std::string requestHeader;

        std::string method = request.method == Method::Get ? "GET" : "POST";

        requestHeader += method + " " + path + " HTTP/1.1\r\n";
        requestHeader += "Host: " + hostHeader + "\r\n";
        requestHeader += "Connection: close\r\n";

        for (const auto &[key, value] : request.headers)
        {
            requestHeader += key + ": " + value + "\r\n";
        }

        if (request.cookies.size() > 0)
        {
            requestHeader += "Cookie: ";

            for (size_t i = 0; i < request.cookies.size(); i++)
            {
                requestHeader += request.cookies[i] + "; ";
            }

            requestHeader += "\r\n";
        }

        if (request.content)
        {
            requestHeader += "Content-Length: " + std::to_string(request.content->GetLength()) + "\r\n";
            requestHeader += "Content-Type: " + request.contentType + "\r\n";
        }

        requestHeader += "\r\n";

        const uint8_t *ptr = reinterpret_cast<const uint8_t *>(requestHeader.data());
        size_t totalSent = 0;

        while (totalSent < requestHeader.size())
        {
            int64_t bytesSent = 0;

            if (ssl)
                bytesSent = SSL_write(ssl, ptr + totalSent, requestHeader.size() - totalSent);
            else
                bytesSent = socket->Write(ptr + totalSent, requestHeader.size() - totalSent);

            if (bytesSent <= 0)
            {
                if (SOCKET_ERROR == SOCKET_EGAIN || SOCKET_ERROR == SOCKET_EWOULDBLOCK)
                    continue;

                CloseConnection(socket.get(), ssl);
                return std::make_shared<Response>();
            }

            totalSent += bytesSent;
        }

        totalSent = 0;
        char tempBuffer[8192];

        if (request.content)
        {
            uint64_t contentLength = request.content->GetLength();

            while (totalSent < contentLength)
            {
                int64_t readOffset = request.content->GetReadOffset();
                int64_t bytesRead = request.content->Read(tempBuffer, 8192);

                if (bytesRead > 0)
                {
                    int64_t bytesSent = 0;

                    if (ssl)
                        bytesSent = SSL_write(ssl, tempBuffer, bytesRead);
                    else
                        bytesSent = socket->Write(tempBuffer, bytesRead);

                    if (bytesSent <= 0)
                    {
                        if (SOCKET_ERROR == SOCKET_EGAIN || SOCKET_ERROR == SOCKET_EWOULDBLOCK)
                        {
                            request.content->Seek(readOffset, SeekOrigin::Begin);
                            continue;
                        }

                        CloseConnection(socket.get(), ssl);
                        return std::make_shared<Response>();
                    }

                    if (bytesSent != bytesRead)
                        request.content->Seek(readOffset, SeekOrigin::Begin);

                    totalSent += bytesSent;
                }
                else
                {
                    CloseConnection(socket.get(), ssl);
                    return std::make_shared<Response>();
                }
            }
        }

        std::string responseHeader;

        while (true)
        {
            int64_t bytesRead = 0;

            if (ssl)
                bytesRead = SSL_read(ssl, tempBuffer, sizeof(tempBuffer));
            else
                bytesRead = socket->Read(tempBuffer, sizeof(tempBuffer));

            if (bytesRead > 0)
            {
                responseHeader.append(tempBuffer, bytesRead);
                size_t headerEnd = responseHeader.find("\r\n\r\n");

                if (headerEnd != std::string::npos)
                {
                    std::string actualHeader = responseHeader.substr(0, headerEnd);
                    std::shared_ptr<Response> response = std::make_shared<Response>();

                    ParseHeaders(actualHeader, response.get());

                    size_t headerTotalSize = headerEnd + 4;
                    size_t leftOverSize = responseHeader.size() - headerTotalSize;

                    if (leftOverSize > 0)
                    {
                        std::string initialContent = responseHeader.substr(headerTotalSize);
                        response->content = std::make_shared<ContentStream>(socket, ssl, initialContent.data(), initialContent.size(), response->transferEncoding, response->contentEncoding);
                    }
                    else
                    {
                        response->content = std::make_shared<ContentStream>(socket, ssl, nullptr, 0, response->transferEncoding, response->contentEncoding);
                    }

                    return response;
                }
            }
            else
            {
                if (SOCKET_ERROR == SOCKET_EGAIN || SOCKET_ERROR == SOCKET_EWOULDBLOCK)
                    continue;

                CloseConnection(socket.get(), ssl);

                return std::make_shared<Response>();
            }
        }
    }

    bool Client::ParseHeaders(const std::string &headerText, Response *response)
    {
        std::istringstream stream(headerText);
        std::string line;

        auto parseUInt32 = [](const std::string &s, uint32_t &v) -> bool
        {
            try
            {
                v = std::stoi(s);
                return true;
            }
            catch (...)
            {
                return false;
            }
        };

        auto parseUInt64 = [](const std::string &s, uint64_t &v) -> bool
        {
            try
            {
                v = std::stoull(s);
                return true;
            }
            catch (...)
            {
                return false;
            }
        };

        auto getHeaderOptions = [](const std::string &value, std::vector<std::string> &options) -> void
        {
            size_t start = 0;
            size_t end = value.find(',');

            while (end != std::string::npos)
            {
                std::string option = value.substr(start, end - start);

                // Trim whitespace
                option.erase(0, option.find_first_not_of(" "));
                option.erase(option.find_last_not_of(" ") + 1);

                if (!option.empty())
                {
                    options.push_back(option);
                }

                start = end + 1;
                end = value.find(',', start);
            }

            // Handle the last (or only) option
            std::string lastOption = value.substr(start);
            lastOption.erase(0, lastOption.find_first_not_of(" "));
            lastOption.erase(lastOption.find_last_not_of(" ") + 1);

            if (!lastOption.empty())
            {
                options.push_back(lastOption);
            }
        };

        auto toLower = [](std::string data) -> std::string
        {
            std::transform(data.begin(), data.end(), data.begin(), [](unsigned char c)
                           { return std::tolower(c); });

            return data;
        };

        // Parse the Status Line (e.g., "HTTP/1.1 200 OK")
        if (std::getline(stream, line))
        {
            std::stringstream ss(line);
            std::string protocol;
            std::string codeStr;

            ss >> protocol; // Usually "HTTP/1.1"
            ss >> codeStr;  // This is the status code "200", "404", etc.

            uint32_t statusCode = 0;
            if (!parseUInt32(codeStr, statusCode))
                return false;
            response->status = static_cast<StatusCode>(statusCode);
        }

        while (std::getline(stream, line) && line != "\r")
        {
            if (!line.empty() && line.back() == '\r')
            {
                line.pop_back();
            }

            size_t colonPos = line.find(": ");
            if (colonPos != std::string::npos)
            {
                std::string key = line.substr(0, colonPos);
                std::string value = line.substr(colonPos + 2);
                std::string keyLowerCase = toLower(key);

                if (keyLowerCase == "set-cookie")
                {
                    response->cookies.push_back(value);
                }
                else
                {
                    response->headers[key] = value;
                }

                if (keyLowerCase == "content-length")
                {
                    if (!parseUInt64(value, response->contentLength))
                        return false;
                }

                if (keyLowerCase == "transfer-encoding")
                {
                    std::vector<std::string> options;
                    getHeaderOptions(value, options);
                    for (size_t i = 0; i < options.size(); i++)
                    {
                        std::string option = toLower(options[i]);
                        if (option == "chunked")
                            response->transferEncoding.push_back(Encoding::Chunked);
                        else if (option == "compress")
                            response->transferEncoding.push_back(Encoding::Compress);
                        else if (option == "deflate")
                            response->transferEncoding.push_back(Encoding::Deflate);
                        else if (option == "gzip")
                            response->transferEncoding.push_back(Encoding::GZip);
                    }
                }

                if (keyLowerCase == "content-encoding")
                {
                    std::vector<std::string> options;
                    getHeaderOptions(value, options);
                    for (size_t i = 0; i < options.size(); i++)
                    {
                        std::string option = toLower(options[i]);
                        if (option == "chunked")
                            response->contentEncoding.push_back(Encoding::Chunked);
                        else if (option == "compress")
                            response->contentEncoding.push_back(Encoding::Compress);
                        else if (option == "deflate")
                            response->contentEncoding.push_back(Encoding::Deflate);
                        else if (option == "gzip")
                            response->contentEncoding.push_back(Encoding::GZip);
                    }
                }
            }
        }

        return true;
    }

    void Client::CloseConnection(Socket *socket, SSL *ssl)
    {
        if (ssl)
        {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        socket->Close();
    }
}
