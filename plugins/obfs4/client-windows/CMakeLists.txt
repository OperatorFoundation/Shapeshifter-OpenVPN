cmake_minimum_required(VERSION 3.10)
project(shapeshifter_plugin_obfs4 C)

set(CMAKE_C_STANDARD 11)

include_directories(include)
include_directories(src)

add_library(shapeshifter_plugin_obfs4 SHARED
        src/shapeshifter-obfs4-win32.c
        src/shapeshifter-obfs4.c)

find_library(CGOLIB NAMES shapeshifter-obfs4-go.lib shapeshifter-obfs4-go HINTS lib)

target_link_libraries(shapeshifter_plugin_obfs4 ${CGOLIB} wsock32 ws2_32 Winmm)