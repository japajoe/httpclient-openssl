#ifndef HTTPCLIENT_HPP
#define HTTPCLIENT_HPP

#include <cstdint>
#include <cstdlib>
#include <string>
#include <fstream>
#include <memory>
#include <unordered_map>
#include <vector>

namespace Http
{
    typedef void SSL_CTX;
    typedef void SSL;

    class Socket
    {
    public:
        Socket();
        ~Socket();
        Socket(const Socket &other);
        Socket(Socket &&other) noexcept;
        Socket &operator=(const Socket &other);
        Socket &operator=(Socket &&other) noexcept;
        bool Connect(const std::string &ip, uint16_t port);
        void Close();
        void Shutdown();
        int64_t Read(void *buffer, uint64_t size);
        int64_t Write(const void *buffer, uint64_t size);
        int32_t GetDescriptor() const;
    private:
        int32_t descriptor;
    };

    enum SeekOrigin
    {
        Begin,
        Current,
        End
    };

    enum FileAccess
    {
        Read,
        Write,
        ReadWrite
    };

    class Stream
    {
    public:
        virtual ~Stream() = default;
        virtual int64_t Read(void *buffer, size_t size) = 0;
        virtual int64_t Write(const void *buffer, size_t size) = 0;
        virtual int64_t Seek(int64_t offset, SeekOrigin origin) = 0;
        virtual int64_t GetReadOffset() = 0;
        int64_t GetLength() const { return length; }
    protected:
        int64_t readPosition = 0;
        int64_t writePosition = 0;
        int64_t length = 0;
    };

    class MemoryStream : public Stream
    {
    public:
        MemoryStream(void *memory, size_t size, bool copyMemory);
        ~MemoryStream();
        int64_t Read(void *buffer, size_t size) override;
        int64_t Write(const void *buffer, size_t size) override;
        int64_t Seek(int64_t offset, SeekOrigin origin) override;
        int64_t GetReadOffset() override;
    private:
        void *memory;
        size_t size;
        bool copyMemory;
    };

    class FileStream : public Stream
    {
    public:
        FileStream(const std::string &filePath, FileAccess access);
        ~FileStream();
        int64_t Read(void *buffer, size_t size) override;
        int64_t Write(const void *buffer, size_t size) override;
        int64_t Seek(int64_t offset, SeekOrigin origin) override;
        int64_t GetReadOffset() override;
    private:
        FileAccess access;
        std::fstream file;
    };

    class ContentStream : public Stream
    {
    public:
        ContentStream();
        ContentStream(std::shared_ptr<Socket> socket, SSL *ssl, void *initialContent, size_t initialContentLength);
        ~ContentStream();
        int64_t Read(void *buffer, size_t size) override;
        int64_t Write(const void *buffer, size_t size) override;
        int64_t Seek(int64_t offset, SeekOrigin origin) override;
        int64_t GetReadOffset() override;
        void Dispose();
    private:
        std::shared_ptr<Socket> socket;
        SSL *ssl;
        void *initialContent;
        uint64_t initialContentLength;
        uint64_t initialContentConsumed;        
    };

    enum class Method
    {
        Get,
        Post,
        Put,
        Delete,
        Patch,
        Head,
        Options,
        Connect,
        Trace
    };

    enum class StatusCode
    {
        Unknown = 0,
        // 1xx: Informational
        Continue = 100,
        SwitchingProtocols = 101,
        Processing = 102,
        EarlyHints = 103,

        // 2xx: Success
        Ok = 200,
        Created = 201,
        Accepted = 202,
        NonAuthoritativeInformation = 203,
        NoContent = 204,
        ResetContent = 205,
        PartialContent = 206,
        MultiStatus = 207,
        AlreadyReported = 208,
        ImUsed = 226,

        // 3xx: Redirection
        MultipleChoices = 300,
        MovedPermanently = 301,
        Found = 302,
        SeeOther = 303,
        NotModified = 304,
        UseProxy = 305,
        TemporaryRedirect = 307,
        PermanentRedirect = 308,

        // 4xx: Client Error
        BadRequest = 400,
        Unauthorized = 401,
        PaymentRequired = 402,
        Forbidden = 403,
        NotFound = 404,
        MethodNotAllowed = 405,
        NotAcceptable = 406,
        ProxyAuthenticationRequired = 407,
        RequestTimeout = 408,
        Conflict = 409,
        Gone = 410,
        LengthRequired = 411,
        PreconditionFailed = 412,
        PayloadTooLarge = 413,
        UriTooLong = 414,
        UnsupportedMediaType = 415,
        RangeNotSatisfiable = 416,
        ExpectationFailed = 417,
        ImATeapot = 418,
        MisdirectedRequest = 421,
        UnprocessableEntity = 422,
        Locked = 423,
        FailedDependency = 424,
        TooEarly = 425,
        UpgradeRequired = 426,
        PreconditionRequired = 428,
        TooManyRequests = 429,
        RequestHeaderFieldsTooLarge = 431,
        UnavailableForLegalReasons = 451,

        // 5xx: Server Error
        InternalServerError = 500,
        NotImplemented = 501,
        BadGateway = 502,
        ServiceUnavailable = 503,
        GatewayTimeout = 504,
        HttpVersionNotSupported = 505,
        VariantAlsoNegotiates = 506,
        InsufficientStorage = 507,
        LoopDetected = 508,
        NotExtended = 510,
        NetworkAuthenticationRequired = 511
    };

    enum class TransferEncoding
    {
        None = 0,
        Identity = None,
        Chunked,
        Compress,
        Deflate,
        GZip
    };

    class Client;

    class Request
    {
    friend class Client;
    public:
        Request(Method method, const std::string &url);
        Method GetMethod() const;
        std::string &GetUrl();
        std::unordered_map<std::string,std::string> &GetHeaders();
        std::vector<std::string> &Getcookies();
        void AddHeader(const std::string &key, const std::string &value);
        void SetCookie(const std::string &cookie);
        void SetContent(Stream *content, const std::string &contentType);
    private:
        Method method;
        std::string url;
        std::string contentType;
        std::unordered_map<std::string,std::string> headers;
        std::vector<std::string> cookies;
        Stream *content;
    };

    class Response
    {
    friend class Client;
    public:
        Response();
        StatusCode GetStatus() const;
        std::unordered_map<std::string,std::string> &GetHeaders();
        std::vector<std::string> &Getcookies();
        ContentStream *GetContent() const;
        bool GetContentAsString(std::string &str);
        uint64_t GetContentLength() const;
        void Dispose();
    private:
        StatusCode status;
        uint64_t contentLength;        
        std::unordered_map<std::string,std::string> headers;
        std::vector<std::string> cookies;
        std::vector<TransferEncoding> encoding;
        std::shared_ptr<ContentStream> content;
    };

    class Uri
    {
    public:
        static bool TryParse(const std::string &uri, Uri &result);
        std::string GetHost() const;
        std::string GetPathAndQueuery() const;
        std::string GetScheme() const;
        std::string GetIP() const;
        uint16_t GetPort() const;
        bool IsDefaultPort() const;
    private:
        std::string host;
        std::string pathAndQueuery;
        std::string scheme;
        std::string ip;
        uint16_t port;
        bool isDefaultPort;
    };

    class Client
    {
    public:
        Client();
        Client(Client &&other) noexcept;
        Client(const Client &other) = delete;
        ~Client();
        Client &operator=(Client &&other) noexcept;
        Client &operator=(const Client &other) = delete;
        std::shared_ptr<Response> Send(const Request &request);
    private:
        SSL_CTX *sslContext;
        bool ParseHeaders(const std::string &headerText, Response *response);
        void CloseConnection(Socket *socket, SSL *ssl);
    };
}

#endif
