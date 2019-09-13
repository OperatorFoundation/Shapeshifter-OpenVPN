cmake_minimum_required(VERSION 3.10)
project(shapeshifter_plugin_shadow C)

set(CMAKE_C_STANDARD 11)

include_directories(include)
include_directories(src)

add_library(shapeshifter_plugin_shadow SHARED
        src/shapeshifter-shadow-win32.c
        src/shapeshifter-shadow.c)

find_library(CGOLIB NAMES shapeshifter-shadow-go.lib shapeshifter-shadow-go HINTS lib)

target_link_libraries(shapeshifter_plugin_shadow ${CGOLIB} wsock32 ws2_32 Winmm)