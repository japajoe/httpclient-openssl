#ifndef HTTP_PLATFORM_HPP
#define HTTP_PLATFORM_HPP

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

#endif