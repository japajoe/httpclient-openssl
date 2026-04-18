cmake_minimum_required(VERSION 3.15)
project(httpclient)

set(CMAKE_CXX_STANDARD 20)

if(CMAKE_CXX_COMPILER MATCHES "mingw")
    set(WIN32 TRUE)
    set(CMAKE_SYSTEM_NAME Windows)
endif()

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Default build type" FORCE)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DNDEBUG")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -DNDEBUG")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -g0")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -g0")
endif()


file(GLOB_RECURSE SOURCES src/*.cpp)

add_library(${PROJECT_NAME} STATIC ${SOURCES})

if(UNIX)
    set(DLL_DIR "${PROJECT_SOURCE_DIR}/runtimes")

    set(NETWORK_DLLS
        "${DLL_DIR}/libssl.so.3"
        "${DLL_DIR}/libcrypto.so.3"
        "${DLL_DIR}/libz.so.1.3.2"
    )

    foreach(dll ${NETWORK_DLLS})
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${dll}"
            "$<TARGET_FILE_DIR:${PROJECT_NAME}>"
        )
    endforeach()
    target_link_libraries(${PROJECT_NAME} pthread -ldl)
elseif(WIN32)
    set(DLL_DIR "${PROJECT_SOURCE_DIR}/runtimes")

    set(NETWORK_DLLS
        "${DLL_DIR}/libssl-3-x64.dll"
        "${DLL_DIR}/libcrypto-3-x64.dll"
        "${DLL_DIR}/zlib1.dll"
    )

    foreach(dll ${NETWORK_DLLS})
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${dll}"
            "$<TARGET_FILE_DIR:${PROJECT_NAME}>"
        )
    endforeach()
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_link_libraries(${PROJECT_NAME} -static ws2_32)
    else()
        target_link_libraries(${PROJECT_NAME} ws2_32)
    endif()
endif()

target_include_directories(${PROJECT_NAME} PUBLIC 
    "${PROJECT_SOURCE_DIR}/include/HttpClient"
)