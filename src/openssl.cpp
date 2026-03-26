#include "openssl.hpp"
#include "Platform.hpp"
#include "Runtime.hpp"
#if defined(HTTP_PLATFORM_UNIX)
#include <signal.h>
#endif
#include <iostream>

namespace Http
{


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

    static void *pLibraryHandleSsl = nullptr;
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
        if (pLibraryHandleSsl)
        {
            return true;
        }

        std::string libraryPath;

#if defined(HTTP_PLATFORM_WINDOWS)
        libraryPath = "runtimes/libssl-3-x64.dll";
#elif defined(HTTP_PLATFORM_LINUX)
        // Runtime::FindLibraryPath("libssl.so", libraryPath);
        libraryPath = "runtimes/libssl.so.3";
#else
        return false;
#endif
        if (libraryPath.size() > 0)
        {
#if defined(HTTP_PLATFORM_LINUX)
            pLibCryptoHandle = Runtime::LoadLibrary("runtimes/libcrypto.so.3");
#endif
            pLibraryHandleSsl = Runtime::LoadLibrary(libraryPath);

            if (!pLibraryHandleSsl)
            {
                std::cout << "Failed to load " << libraryPath << '\n';
                return false;
            }

            SSL_CTX_new_ptr = (SSL_CTX_new_t)Runtime::GetSymbol(pLibraryHandleSsl, "SSL_CTX_new");
            TLS_method_ptr = (TLS_method_t)Runtime::GetSymbol(pLibraryHandleSsl, "TLS_method");
            TLS_client_method_ptr = (TLS_client_method_t)Runtime::GetSymbol(pLibraryHandleSsl, "TLS_client_method");
            SSL_new_ptr = (SSL_new_t)Runtime::GetSymbol(pLibraryHandleSsl, "SSL_new");
            SSL_set_fd_ptr = (SSL_set_fd_t)Runtime::GetSymbol(pLibraryHandleSsl, "SSL_set_fd");
            SSL_ctrl_ptr = (SSL_ctrl_t)Runtime::GetSymbol(pLibraryHandleSsl, "SSL_ctrl");
            SSL_connect_ptr = (SSL_connect_t)Runtime::GetSymbol(pLibraryHandleSsl, "SSL_connect");
            SSL_read_ptr = (SSL_read_t)Runtime::GetSymbol(pLibraryHandleSsl, "SSL_read");
            SSL_write_ptr = (SSL_write_t)Runtime::GetSymbol(pLibraryHandleSsl, "SSL_write");
            SSL_peek_ptr = (SSL_peek_t)Runtime::GetSymbol(pLibraryHandleSsl, "SSL_peek");
            SSL_shutdown_ptr = (SSL_shutdown_t)Runtime::GetSymbol(pLibraryHandleSsl, "SSL_shutdown");
            SSL_free_ptr = (SSL_free_t)Runtime::GetSymbol(pLibraryHandleSsl, "SSL_free");
            SSL_get_error_ptr = (SSL_get_error_t)Runtime::GetSymbol(pLibraryHandleSsl, "SSL_get_error");
            SSL_CTX_free_ptr = (SSL_CTX_free_t)Runtime::GetSymbol(pLibraryHandleSsl, "SSL_CTX_free");
            SSL_CTX_set_verify_ptr = (SSL_CTX_set_verify_t)Runtime::GetSymbol(pLibraryHandleSsl, "SSL_CTX_set_verify");

#if defined(HTTP_PLATFORM_UNIX)
            signal(SIGPIPE, OnSignal);
#endif
            return true;
        }

        return false;
    }

    void SSL_library_unload(void)
    {
        if (!pLibraryHandleSsl)
            return;
        Runtime::UnloadLibrary(pLibraryHandleSsl);
        pLibraryHandleSsl = nullptr;
        if(pLibCryptoHandle)
            Runtime::UnloadLibrary(pLibCryptoHandle);
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
}