#include "HttpClient.hpp"
#include <utility>
#include <atomic>
#include <cassert>
#include <filesystem>
#include <iostream>
#include <cstring>
#include <algorithm>

#if defined(_WIN32) || defined(_WIN64)
#define HTTP_PLATFORM_WINDOWS
#endif

#if defined(__linux__) || defined(__FreeBSD__) || defined(__APPLE__)
#define HTTP_PLATFORM_UNIX
#endif

#if defined(__linux__)
#define HTTP_PLATFORM_LINUX
#endif

#if defined(__FreeBSD__)
#define HTTP_PLATFORM_BSD
#endif

#if defined(__APPLE__)
#define HTTP_PLATFORM_MAC
#endif

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
#include <dlfcn.h>
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
        }
        gSocketCount.store(true);
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

    int32_t Socket::GetDescriptor() const
    {
        return descriptor;
    }

    // ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗███╗   ███╗███████╗
    // ██╔══██╗██║   ██║████╗  ██║╚══██╔══╝██║████╗ ████║██╔════╝
    // ██████╔╝██║   ██║██╔██╗ ██║   ██║   ██║██╔████╔██║█████╗
    // ██╔══██╗██║   ██║██║╚██╗██║   ██║   ██║██║╚██╔╝██║██╔══╝
    // ██║  ██║╚██████╔╝██║ ╚████║   ██║   ██║██║ ╚═╝ ██║███████╗
    // ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝     ╚═╝╚══════╝

    class Runtime
    {
    public:
        static void *LoadLibrary(const std::string &filePath)
        {
            if (!std::filesystem::exists(std::filesystem::path(filePath)))
            {
                std::cout << "File not found: " << filePath << '\n';
                return nullptr;
            }

            void *moduleHandle = nullptr;

#if defined(HTTP_PLATFORM_WINDOWS)
            moduleHandle = (void *)LoadLibrary(filePath.c_str());
            if (!moduleHandle)
                std::cout << "Failed to load library: " << filePath << '\n';
#elif defined(HTTP_PLATFORM_UNIX)
            moduleHandle = dlopen(filePath.c_str(), RTLD_LAZY);
            if (!moduleHandle)
            {
                char *error = dlerror();
                std::cout << "Failed to load library: " << filePath << ". Error: " << error << '\n';
            }
#endif

            return moduleHandle;
        }

        static void UnloadLibrary(void *libraryHandle)
        {
            if (!libraryHandle)
                return;
#if defined(HTTP_PLATFORM_WINDOWS)
            FreeLibrary((HINSTANCE)libraryHandle);
#elif defined(HTTP_PLATFORM_UNIX)
            dlclose(libraryHandle);
#endif
        }

        static void *GetSymbol(void *libraryHandle, const std::string &symbolName)
        {
            if (!libraryHandle)
                return nullptr;

            void *s = nullptr;

#if defined(HTTP_PLATFORM_WINDOWS)
            s = (void *)GetProcAddress((HINSTANCE)libraryHandle, symbolName.c_str());
            if (s == nullptr)
                std::cout << "Error: undefined symbol: " << symbolName << '\n';
#elif defined(HTTP_PLATFORM_UNIX)
            dlerror(); /* clear error code */
            s = dlsym(libraryHandle, symbolName.c_str());
            char *error = dlerror();

            if (error != nullptr)
                std::cout << "Error: " << error << '\n';
#endif

            return s;
        }

        static bool FindLibraryPath(const std::string &libraryName, std::string &libraryPath)
        {
#if defined(HTTP_PLATFORM_WINDOWS)
            static char result[4096]; // Static buffer to hold result
            DWORD res = SearchPath(nullptr, libraryName.c_str(), nullptr, MAX_PATH, result, nullptr);
            if (res == 0)
                return false;
            int len = strlen(result);
            char *outputPath = new char[len + 1];
            std::memcpy(outputPath, result, len);
            outputPath[len] = '\0';
            libraryPath = std::string(outputPath);
            delete[] outputPath;
            return true;
#elif defined(HTTP_PLATFORM_LINUX) || defined(HTTP_PLATFORM_BSD)
            // Prepare the command to search the library
            char cmd[256];

#ifdef HTTP_PLATFORM_LINUX
            snprintf(cmd, sizeof(cmd), "ldconfig -p 2>/dev/null | grep %s", libraryName.c_str());
#else
            snprintf(cmd, sizeof(cmd), "ldconfig -r | grep %s", libraryName.c_str());
#endif

            FILE *pipe = popen(cmd, "r");

            if (!pipe)
            {
                std::cout << "popen() failed\n";
                return false;
            }

            static char result[4096]; // Static buffer to hold result

            while (fgets(result, sizeof(result), pipe) != NULL)
            {
                // Find the path after the "=>" symbol
                char *pos = strstr(result, "=>");
                if (pos != NULL)
                {
                    pos += 2; // Move pointer to the path
                    // Trim whitespace
                    while (*pos == ' ')
                        pos++;
                    // Remove newline character
                    char *newline = strchr(pos, '\n');
                    if (newline)
                        *newline = '\0';
                    pclose(pipe);
                    int len = strlen(pos);
                    char *outputPath = new char[len + 1];
                    std::memcpy(outputPath, pos, len);
                    outputPath[len] = '\0';
                    libraryPath = std::string(outputPath);
                    delete[] outputPath;
                    return true;
                }
            }

            pclose(pipe);
            return false;
#elif defined(HTTP_PLATFORM_MAC)
            return false;
#else
            return false;
#endif
        }
    };

    //  ██████╗ ██████╗ ███████╗███╗   ██╗███████╗███████╗██╗
    // ██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██╔════╝██║
    // ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗███████╗██║
    // ██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║╚════██║╚════██║██║
    // ╚██████╔╝██║     ███████╗██║ ╚████║███████║███████║███████╗
    //  ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝

    typedef struct ssl_method_st SSL_METHOD;
    typedef struct x509_store_ctx_st X509_STORE_CTX;
    typedef int (*SSL_verify_cb)(int preverify_ok, X509_STORE_CTX *x509_ctx);

#define SSL_CTRL_SET_TLSEXT_HOSTNAME 55
#define TLSEXT_NAMETYPE_host_name 0
#define SSL_ERROR_NONE 0
#define SSL_ERROR_SSL 1
#define SSL_ERROR_WANT_READ 2
#define SSL_ERROR_WANT_WRITE 3
#define SSL_ERROR_WANT_X509_LOOKUP 4
#define SSL_ERROR_SYSCALL 5 // look at error stack/return value/errno

    typedef SSL_CTX *(*SSL_CTX_new_t)(const SSL_METHOD *meth);
    typedef const SSL_METHOD *(*TLS_method_t)(void);
    typedef const SSL_METHOD *(*TLS_client_method_t)(void);
    typedef SSL *(*SSL_new_t)(SSL_CTX *ctx);
    typedef int (*SSL_set_fd_t)(SSL *s, int fd);
    typedef long (*SSL_ctrl_t)(SSL *ssl, int cmd, long larg, void *parg);
    typedef int (*SSL_connect_t)(SSL *ssl);
    typedef int (*SSL_read_t)(SSL *ssl, void *buf, int num);
    typedef int (*SSL_write_t)(SSL *ssl, const void *buf, int num);
    typedef int (*SSL_peek_t)(SSL *ssl, void *buf, int num);
    typedef int (*SSL_shutdown_t)(SSL *s);
    typedef void (*SSL_free_t)(SSL *ssl);
    typedef int (*SSL_get_error_t)(const SSL *s, int ret_code);
    typedef void (*SSL_CTX_free_t)(SSL_CTX *ctx);
    typedef void (*SSL_CTX_set_verify_t)(SSL_CTX *ctx, int mode, SSL_verify_cb callback);

    static void *pLibraryHandle = nullptr;
    static void *pLibCryptoHandle = nullptr;
    static SSL_CTX_new_t SSL_CTX_new_ptr = nullptr;
    static TLS_method_t TLS_method_ptr = nullptr;
    static TLS_client_method_t TLS_client_method_ptr = nullptr;
    static SSL_new_t SSL_new_ptr = nullptr;
    static SSL_set_fd_t SSL_set_fd_ptr = nullptr;
    static SSL_ctrl_t SSL_ctrl_ptr = nullptr;
    static SSL_connect_t SSL_connect_ptr = nullptr;
    static SSL_read_t SSL_read_ptr = nullptr;
    static SSL_write_t SSL_write_ptr = nullptr;
    static SSL_peek_t SSL_peek_ptr = nullptr;
    static SSL_shutdown_t SSL_shutdown_ptr = nullptr;
    static SSL_free_t SSL_free_ptr = nullptr;
    static SSL_get_error_t SSL_get_error_ptr = nullptr;
    static SSL_CTX_free_t SSL_CTX_free_ptr = nullptr;
    static SSL_CTX_set_verify_t SSL_CTX_set_verify_ptr = nullptr;

    static void OnSignal(int s)
    {
        if (s == SIGPIPE)
        {
            printf("Broken pipe\n");
            return;
        }
    }

    bool SSL_library_load(void)
    {
        if (pLibraryHandle)
        {
            return true;
        }

        std::string libraryPath;

#if defined(HTTP_PLATFORM_WINDOWS)
        libraryPath = "libssl-3-x64.dll";
#elif defined(HTTP_PLATFORM_LINUX) || defined(HTTP_PLATFORM_BSD)
        Runtime::FindLibraryPath("libssl.so", libraryPath);
        // libraryPath = "./libssl.so.3";
#else
        return false;
#endif
        if (libraryPath.size() > 0)
        {
#if defined(HTTP_PLATFORM_LINUX) && 0
            pLibCryptoHandle = Runtime::LoadLibrary("./libcrypto.so.3");
#endif
            pLibraryHandle = Runtime::LoadLibrary(libraryPath);

            if (!pLibraryHandle)
            {
                std::cout << "Failed to load " << libraryPath << '\n';
                return false;
            }

            SSL_CTX_new_ptr = (SSL_CTX_new_t)Runtime::GetSymbol(pLibraryHandle, "SSL_CTX_new");
            TLS_method_ptr = (TLS_method_t)Runtime::GetSymbol(pLibraryHandle, "TLS_method");
            TLS_client_method_ptr = (TLS_client_method_t)Runtime::GetSymbol(pLibraryHandle, "TLS_client_method");
            SSL_new_ptr = (SSL_new_t)Runtime::GetSymbol(pLibraryHandle, "SSL_new");
            SSL_set_fd_ptr = (SSL_set_fd_t)Runtime::GetSymbol(pLibraryHandle, "SSL_set_fd");
            SSL_ctrl_ptr = (SSL_ctrl_t)Runtime::GetSymbol(pLibraryHandle, "SSL_ctrl");
            SSL_connect_ptr = (SSL_connect_t)Runtime::GetSymbol(pLibraryHandle, "SSL_connect");
            SSL_read_ptr = (SSL_read_t)Runtime::GetSymbol(pLibraryHandle, "SSL_read");
            SSL_write_ptr = (SSL_write_t)Runtime::GetSymbol(pLibraryHandle, "SSL_write");
            SSL_peek_ptr = (SSL_peek_t)Runtime::GetSymbol(pLibraryHandle, "SSL_peek");
            SSL_shutdown_ptr = (SSL_shutdown_t)Runtime::GetSymbol(pLibraryHandle, "SSL_shutdown");
            SSL_free_ptr = (SSL_free_t)Runtime::GetSymbol(pLibraryHandle, "SSL_free");
            SSL_get_error_ptr = (SSL_get_error_t)Runtime::GetSymbol(pLibraryHandle, "SSL_get_error");
            SSL_CTX_free_ptr = (SSL_CTX_free_t)Runtime::GetSymbol(pLibraryHandle, "SSL_CTX_free");
            SSL_CTX_set_verify_ptr = (SSL_CTX_set_verify_t)Runtime::GetSymbol(pLibraryHandle, "SSL_CTX_set_verify");

#if defined(HTTP_PLATFORM_UNIX) || defined(HTTP_PLATFORM_BSD)
            signal(SIGPIPE, OnSignal);
            // signal(SIGPIPE, SIG_IGN);
            // SIG_IGN
#endif
            return true;
        }

        return false;
    }

    void SSL_library_unload(void)
    {
        if (!pLibraryHandle)
            return;
        Runtime::UnloadLibrary(pLibraryHandle);
        pLibraryHandle = nullptr;
        pLibCryptoHandle = nullptr;
    }

    SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth)
    {
        return SSL_CTX_new_ptr(meth);
    }

    const SSL_METHOD *TLS_method(void)
    {
        return TLS_method_ptr();
    }

    const SSL_METHOD *TLS_client_method(void)
    {
        return TLS_client_method_ptr();
    }

    SSL *SSL_new(SSL_CTX *ctx)
    {
        return SSL_new_ptr(ctx);
    }

    int SSL_set_fd(SSL *s, int fd)
    {
        return SSL_set_fd_ptr(s, fd);
    }

    long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg)
    {
        return SSL_ctrl_ptr(ssl, cmd, larg, parg);
    }

    int SSL_connect(SSL *ssl)
    {
        return SSL_connect_ptr(ssl);
    }

    int SSL_read(SSL *ssl, void *buf, int num)
    {
        return SSL_read_ptr(ssl, buf, num);
    }

    int SSL_write(SSL *ssl, const void *buf, int num)
    {
        return SSL_write_ptr(ssl, buf, num);
    }

    int SSL_peek(SSL *ssl, void *buf, int num)
    {
        return SSL_peek_ptr(ssl, buf, num);
    }

    int SSL_shutdown(SSL *s)
    {
        return SSL_shutdown_ptr(s);
    }

    void SSL_free(SSL *ssl)
    {
        return SSL_free_ptr(ssl);
    }

    int SSL_get_error(const SSL *s, int ret_code)
    {
        return SSL_get_error_ptr(s, ret_code);
    }

    void SSL_CTX_free(SSL_CTX *ctx)
    {
        return SSL_CTX_free_ptr(ctx);
    }

    void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, SSL_verify_cb callback)
    {
        return SSL_CTX_set_verify_ptr(ctx, mode, callback);
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

    ContentStream::ContentStream()
    {
        socket = nullptr;
        ssl = nullptr;
        initialContent = nullptr;
        initialContentLength = 0;
        initialContentConsumed = 0;
    }

    ContentStream::ContentStream(std::shared_ptr<Socket> socket, SSL *ssl, void *initialContent, size_t initialContentLength)
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
    }

    int64_t ContentStream::Read(void *buffer, size_t size)
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
            sslContext = SSL_CTX_new(TLS_method());
        else
            sslContext = nullptr;
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
                        response->content = std::make_shared<ContentStream>(socket, ssl, initialContent.data(), initialContent.size());
                    }
                    else
                    {
                        response->content = std::make_shared<ContentStream>(socket, ssl, nullptr, 0);
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

        auto getHeaderOptions = [] (const std::string& value, std::vector<std::string>& options) -> void
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
            {
                return std::tolower(c);
            });

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

                if(keyLowerCase == "transfer-encoding")
                {
                    std::vector<std::string> options;
                    getHeaderOptions(value, options);
                    for(size_t i = 0; i < options.size(); i++)
                    {
                        std::string option = toLower(options[i]);
                        if(option == "identity")
                            response->encoding.push_back(TransferEncoding::Identity);
                        else if(option == "chunked")
                            response->encoding.push_back(TransferEncoding::Chunked);
                        else if(option == "compress")
                            response->encoding.push_back(TransferEncoding::Compress);
                        else if(option == "deflate")
                            response->encoding.push_back(TransferEncoding::Deflate);
                        else if(option == "gzip")
                            response->encoding.push_back(TransferEncoding::GZip);
                        else
                            response->encoding.push_back(TransferEncoding::None);
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
