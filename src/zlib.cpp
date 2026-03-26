#include "zlib.hpp"
#include "Runtime.hpp"
#include "Platform.hpp"
#include <iostream>

namespace Http
{
    typedef int (*inflateInit2__t)(z_streamp strm, int windowBits, const char *version, int stream_size);
    typedef int (*inflate_t)(z_streamp strm, int flush);
    typedef int (*inflateEnd_t)(z_streamp strm);

    static void *pLibraryHandleLibZ = nullptr;
    static inflateInit2__t inflateInit2__ptr = nullptr;
    static inflate_t inflate_ptr = nullptr;
    static inflateEnd_t inflateEnd_ptr = nullptr;

    int inflateInit2_(z_streamp strm, int windowBits, const char *version, int stream_size)
    {
        return inflateInit2__ptr(strm, windowBits, version, stream_size);
    }

    int inflate(z_streamp strm, int flush)
    {
        return inflate_ptr(strm, flush);
    }

    int inflateEnd(z_streamp strm)
    {
        return inflateEnd_ptr(strm);
    }

    bool zlib_load_library(void)
    {
        if (pLibraryHandleLibZ)
        {
            return true;
        }

        std::string libraryPath;

#if defined(HTTP_PLATFORM_WINDOWS)
        libraryPath = "runtimes/zlib1.dll";
#elif defined(HTTP_PLATFORM_LINUX)
        // Runtime::FindLibraryPath("libz.so.1", libraryPath);
        libraryPath = "runtimes/libz.so.1.3.2";
#else
        return false;
#endif
        if (libraryPath.size() > 0)
        {
            pLibraryHandleLibZ = Runtime::LoadLibrary(libraryPath);

            if (!pLibraryHandleLibZ)
            {
                std::cout << "Failed to load " << libraryPath << '\n';
                return false;
            }

            inflateInit2__ptr = (inflateInit2__t)Runtime::GetSymbol(pLibraryHandleLibZ, "inflateInit2_");
            inflate_ptr = (inflate_t)Runtime::GetSymbol(pLibraryHandleLibZ, "inflate");
            inflateEnd_ptr = (inflateEnd_t)Runtime::GetSymbol(pLibraryHandleLibZ, "inflateEnd");

            return true;
        }

        return false;
    }

    void zlib_unload_library(void)
    {
        if(!pLibraryHandleLibZ)
            return;
        Runtime::UnloadLibrary(pLibraryHandleLibZ);
        pLibraryHandleLibZ = nullptr;
    }
}