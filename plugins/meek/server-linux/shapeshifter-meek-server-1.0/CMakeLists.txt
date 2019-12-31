cmake_minimum_required(VERSION 3.10)
project(shapeshifter-meek-server C)

set(CMAKE_C_STANDARD 11)

include_directories(include)
include_directories(src)

add_library(shapeshifter-meek-server SHARED
        include/openvpn/openvpn-plugin.h
        include/openvpn/openvpn-vsocket.h
        include/shapeshifter-meek-go.h
        src/shapeshifter-meek-posix.c
        src/shapeshifter-meek.c
        src/shapeshifter-meek.h)

find_library(CGOLIB NAMES shapeshifter-meek-go.a shapeshifter-meek-go HINTS lib)
target_link_libraries(shapeshifter-meek-server ${CGOLIB})

install(TARGETS shapeshifter-meek-server LIBRARY DESTINATION lib)
