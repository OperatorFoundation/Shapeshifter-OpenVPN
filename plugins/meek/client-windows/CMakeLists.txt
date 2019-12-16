cmake_minimum_required(VERSION 3.10)
project(shapeshifter_plugin_meeklite C)

set(CMAKE_C_STANDARD 11)

include_directories(include)
include_directories(src)

add_library(shapeshifter_plugin_meeklite SHARED
        src/shapeshifter-meeklite-win32.c
        src/shapeshifter-meeklite.c)

find_library(CGOLIB NAMES shapeshifter-meeklite-go.lib shapeshifter-meeklite-go HINTS lib)

target_link_libraries(shapeshifter_plugin_meeklite ${CGOLIB} wsock32 ws2_32 Winmm)