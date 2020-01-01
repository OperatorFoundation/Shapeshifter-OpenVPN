cmake_minimum_required(VERSION 3.10)
project(shapeshifter_plugin_meekheavy C)

set(CMAKE_C_STANDARD 11)

include_directories(include)
include_directories(src)

add_library(shapeshifter_plugin_meekheavy SHARED
        src/shapeshifter-meekheavy.c
        src/libmeekheavy.c)

find_library(CURLLIB NAMES libcurl.dll.a libcurl HINTS lib)
find_library(SSLLIB NAMES libssl.dll.a libssl HINTS lib)
find_library(CRYPTOLIB NAMES libcrypto.dll.a libcrypto HINTS lib)

target_link_libraries(shapeshifter_plugin_meekheavy ${CURLLIB} ${SSLLIB} ${CRYPTOLIB} wsock32 ws2_32 Winmm)