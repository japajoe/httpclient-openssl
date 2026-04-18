#ifndef HTTP_RUNTIME_HPP
#define HTTP_RUNTIME_HPP

#include <string>

namespace Http
{
    class Runtime
    {
    public:
        static void *LoadLibraryFromPath(const std::string &filePath);
        static void UnloadLibrary(void *libraryHandle);
        static void *GetSymbol(void *libraryHandle, const std::string &symbolName);
        static bool FindLibraryPath(const std::string &libraryName, std::string &libraryPath);
    };
}

#endif