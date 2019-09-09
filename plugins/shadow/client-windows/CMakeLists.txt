cmake_minimum_required(VERSION 3.10)
project(shapeshifter_plugin_shadow C)

set(CMAKE_C_STANDARD 11)

include_directories(include)
include_directories(src)

add_library(shapeshifter_plugin_shadow SHARED
        include/openvpn/openvpn-plugin.h
        include/openvpn/openvpn-vsocket.h
        include/shapeshifter-shadow-go.h
        src/shapeshifter-shadow-win32.c
        src/shapeshifter-shadow.c
        src/shapeshifter-shadow.h)

find_library(CGOLIB shapeshifter-shadow-go HINTS C:/Users/GCR/CLionProjects/Shapeshifter-OpenVPN/plugins/shadow/client-windows/lib/shapeshifter-shadow-go.a)

target_link_libraries(shapeshifter_plugin_shadow wsock32 ws2_32 ${CGOLIB})