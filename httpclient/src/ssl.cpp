#include "ssl.hpp"
#include "pluginit.h"
#include <iostream>

namespace http
{
	void *ssl::libraryHandle = nullptr;

	typedef SSL_CTX *(*SSL_CTX_new_t)(const SSL_METHOD *meth);
	typedef const SSL_METHOD *(*TLS_method_t)(void);
	typedef SSL *(*SSL_new_t)(SSL_CTX *ctx);
	typedef int (*SSL_set_fd_t)(SSL *s, int fd);
	typedef long (*SSL_ctrl_t)(SSL *ssl, int cmd, long larg, void *parg);
	typedef int (*SSL_connect_t)(SSL *ssl);
	typedef int (*SSL_read_t)(SSL *ssl, void *buf, int num);
	typedef int (*SSL_write_t)(SSL *ssl, const void *buf, int num);
	typedef int (*SSL_peek_t)(SSL *ssl, void *buf, int num);
	typedef int (*SSL_shutdown_t)(SSL *s);
	typedef void (*SSL_free_t)(SSL *ssl);
	typedef void (*SSL_CTX_free_t)(SSL_CTX *ctx);
	typedef void (*SSL_CTX_set_verify_t)(SSL_CTX *ctx, int mode, SSL_verify_cb callback);

	SSL_CTX_new_t SSL_CTX_new_ptr = nullptr;
	TLS_method_t TLS_method_ptr = nullptr;
	SSL_new_t SSL_new_ptr = nullptr;
	SSL_set_fd_t SSL_set_fd_ptr = nullptr;
	SSL_ctrl_t SSL_ctrl_ptr = nullptr;
	SSL_connect_t SSL_connect_ptr = nullptr;
	SSL_read_t SSL_read_ptr = nullptr;
	SSL_write_t SSL_write_ptr = nullptr;
	SSL_peek_t SSL_peek_ptr = nullptr;
	SSL_shutdown_t SSL_shutdown_ptr = nullptr;
	SSL_free_t SSL_free_ptr = nullptr;
	SSL_CTX_free_t SSL_CTX_free_ptr = nullptr;
	SSL_CTX_set_verify_t SSL_CTX_set_verify_ptr = nullptr;

	static bool is_initialized(void *fn, const char *name)
	{
		if(fn)
			return true;
		
		fprintf(stderr, "Failed to loaded function: %s\n", name);
		ssl::close_library();
		return false;
	}

	bool ssl::load_library(const char *libraryPath)
	{
		libraryHandle = pli_plugin_load(libraryPath);

		if(!libraryHandle)
			return false;

		SSL_CTX_new_ptr = (SSL_CTX_new_t)pli_plugin_get_symbol(libraryHandle, "SSL_CTX_new");
		TLS_method_ptr = (TLS_method_t)pli_plugin_get_symbol(libraryHandle, "TLS_method");
		SSL_new_ptr = (SSL_new_t)pli_plugin_get_symbol(libraryHandle, "SSL_new");
		SSL_set_fd_ptr = (SSL_set_fd_t)pli_plugin_get_symbol(libraryHandle, "SSL_set_fd");
		SSL_ctrl_ptr = (SSL_ctrl_t)pli_plugin_get_symbol(libraryHandle, "SSL_ctrl");
		SSL_connect_ptr = (SSL_connect_t)pli_plugin_get_symbol(libraryHandle, "SSL_connect");
		SSL_read_ptr = (SSL_read_t)pli_plugin_get_symbol(libraryHandle, "SSL_read");
		SSL_write_ptr = (SSL_write_t)pli_plugin_get_symbol(libraryHandle, "SSL_write");
		SSL_peek_ptr = (SSL_peek_t)pli_plugin_get_symbol(libraryHandle, "SSL_peek");
		SSL_shutdown_ptr = (SSL_shutdown_t)pli_plugin_get_symbol(libraryHandle, "SSL_shutdown");
		SSL_free_ptr = (SSL_free_t)pli_plugin_get_symbol(libraryHandle, "SSL_free");
		SSL_CTX_free_ptr = (SSL_CTX_free_t)pli_plugin_get_symbol(libraryHandle, "SSL_CTX_free");
		SSL_CTX_set_verify_ptr = (SSL_CTX_set_verify_t)pli_plugin_get_symbol(libraryHandle, "SSL_CTX_set_verify");

		if(!is_initialized((void*)SSL_CTX_new_ptr, "SSL_CTX_new_ptr"))
			return false;
		if(!is_initialized((void*)TLS_method_ptr, "TLS_method_ptr"))
			return false;
		if(!is_initialized((void*)SSL_new_ptr, "SSL_new_ptr"))
			return false;
		if(!is_initialized((void*)SSL_set_fd_ptr, "SSL_set_fd_ptr"))
			return false;
		if(!is_initialized((void*)SSL_ctrl_ptr, "SSL_ctrl_ptr"))
			return false;
		if(!is_initialized((void*)SSL_connect_ptr, "SSL_connect_ptr"))
			return false;
		if(!is_initialized((void*)SSL_read_ptr, "SSL_read_ptr"))
			return false;
		if(!is_initialized((void*)SSL_write_ptr, "SSL_write_ptr"))
			return false;
		if(!is_initialized((void*)SSL_peek_ptr, "SSL_peek_ptr"))
			return false;
		if(!is_initialized((void*)SSL_shutdown_ptr, "SSL_shutdown_ptr"))
			return false;
		if(!is_initialized((void*)SSL_free_ptr, "SSL_free_ptr"))
			return false;
		if(!is_initialized((void*)SSL_CTX_free_ptr, "SSL_CTX_free_ptr"))
			return false;
		if(!is_initialized((void*)SSL_CTX_set_verify_ptr, "SSL_CTX_set_verify_ptr"))
			return false;


		return true;
	}

	void ssl::close_library()
	{
		if(libraryHandle)
			pli_plugin_unload(libraryHandle);
		libraryHandle = nullptr;
	}

	bool ssl::is_loaded()
	{
		return libraryHandle != nullptr;
	}

	SSL_CTX *ssl::SSL_CTX_new(const SSL_METHOD *meth)
	{
		if(!libraryHandle)
			return nullptr;
		return SSL_CTX_new_ptr(meth);
	}

	const SSL_METHOD *ssl::TLS_method(void)
	{
		if(!libraryHandle)
			return nullptr;
		return TLS_method_ptr();
	}

	SSL *ssl::SSL_new(SSL_CTX *ctx)
	{
		if(!libraryHandle)
			return nullptr;
		return SSL_new_ptr(ctx);
	}

	int ssl::SSL_set_fd(SSL *s, int fd)
	{
		if(!libraryHandle)
			return 0;
		return SSL_set_fd_ptr(s, fd);
	}

	long ssl::SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg)
	{
		if(!libraryHandle)
			return 0;
		return SSL_ctrl_ptr(ssl, cmd, larg, parg);
	}

	int ssl::SSL_connect(SSL *ssl)
	{
		if(!libraryHandle)
			return 0;
		return SSL_connect_ptr(ssl);
	}

	int ssl::SSL_read(SSL *ssl, void *buf, int num)
	{
		if(!libraryHandle)
			return 0;
		return SSL_read_ptr(ssl, buf, num);
	}

	int ssl::SSL_write(SSL *ssl, const void *buf, int num)
	{
		if(!libraryHandle)
			return 0;
		return SSL_write_ptr(ssl, buf, num);
	}

	int ssl::SSL_peek(SSL *ssl, void *buf, int num)
	{
		if(!libraryHandle)
			return 0;
		return SSL_peek_ptr(ssl, buf, num);
	}

	int ssl::SSL_shutdown(SSL *s)
	{
		if(!libraryHandle)
			return 0;
		return SSL_shutdown_ptr(s);
	}

	void ssl::SSL_free(SSL *ssl)
	{
		if(!libraryHandle)
			return;
		SSL_free_ptr(ssl);
	}

	void ssl::SSL_CTX_free(SSL_CTX *ctx)
	{
		if(!libraryHandle)
			return;
		SSL_CTX_free_ptr(ctx);
	}

	void ssl::SSL_CTX_set_verify(SSL_CTX *ctx, int mode, SSL_verify_cb callback)
	{
		if(!libraryHandle)
			return;
		SSL_CTX_set_verify_ptr(ctx, mode, callback);
	}
}