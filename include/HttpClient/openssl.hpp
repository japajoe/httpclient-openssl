#ifndef HTTP_OPENSSL_HPP
#define HTTP_OPENSSL_HPP

namespace Http
{
    typedef void SSL_CTX;
    typedef void SSL;

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

    bool SSL_library_load(void);
    void SSL_library_unload(void);
    SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth);
    const SSL_METHOD *TLS_method(void);
    const SSL_METHOD *TLS_client_method(void);
    SSL *SSL_new(SSL_CTX *ctx);
    int SSL_set_fd(SSL *s, int fd);
    long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg);
    int SSL_connect(SSL *ssl);
    int SSL_accept(SSL *ssl);
    int SSL_read(SSL *ssl, void *buf, int num);
    int SSL_write(SSL *ssl, const void *buf, int num);
    int SSL_peek(SSL *ssl, void *buf, int num);
    int SSL_shutdown(SSL *s);
    void SSL_free(SSL *ssl);
    int SSL_get_error(const SSL *s, int ret_code);
    void SSL_CTX_free(SSL_CTX *ctx);
    void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, SSL_verify_cb callback);
}

#endif