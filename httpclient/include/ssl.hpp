#ifndef HTTP_SSL_HPP
#define HTTP_SSL_HPP

#include "openssl/ssl.h"

namespace http
{
	class ssl
	{
	public:
		static bool load_library(const char *libraryPath);
		static void close_library();
		static bool is_loaded();
		static SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth);
		static const SSL_METHOD *TLS_method(void);
		static SSL *SSL_new(SSL_CTX *ctx);
		static int SSL_set_fd(SSL *s, int fd);
		static long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg);
		static int SSL_connect(SSL *ssl);
		static int SSL_read(SSL *ssl, void *buf, int num);
		static int SSL_write(SSL *ssl, const void *buf, int num);
		static int SSL_peek(SSL *ssl, void *buf, int num);
		static int SSL_shutdown(SSL *s);
		static void SSL_free(SSL *ssl);
		static void SSL_CTX_free(SSL_CTX *ctx);
		static void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, SSL_verify_cb callback);
	private:
		static void *libraryHandle;
	};
}

#endif