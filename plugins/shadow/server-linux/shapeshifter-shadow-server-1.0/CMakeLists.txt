cmake_minimum_required(VERSION 3.10)
project(shapeshifter-shadow-server C)

set(CMAKE_C_STANDARD 11)

include_directories(include)
include_directories(src)

add_library(shapeshifter-shadow-server SHARED
        include/openvpn/openvpn-plugin.h
        include/openvpn/openvpn-vsocket.h
        include/shapeshifter-shadow-go.h
        src/shapeshifter-shadow-posix.c
        src/shapeshifter-shadow.c
        src/shapeshifter-shadow.h)

find_library(CGOLIB NAMES shapeshifter-shadow-go.a shapeshifter-shadow-go HINTS lib)
target_link_libraries(shapeshifter-shadow-server ${CGOLIB})

install(TARGETS shapeshifter-shadow-server LIBRARY DESTINATION lib)
