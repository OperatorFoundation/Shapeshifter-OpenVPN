cmake_minimum_required(VERSION 3.10)
project(shapeshifter_plugin_obfs4 C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)

include_directories(include)
include_directories(src)

add_library(shapeshifter_plugin_obfs4 SHARED
        include/openvpn/openvpn-plugin.h
        include/openvpn/openvpn-vsocket.h
        include/shapeshifter-obfs4-go.h
        src/shapeshifter-obfs4-win32.c
        src/shapeshifter-obfs4.c
        src/shapeshifter-obfs4.h)

#find_library(CGOLIB NAMES shapeshifter-obfs4-go.a shapeshifter-obfs4-go HINTS C:/Users/brandon/Documents/Shapeshifter-OpenVPN/plugins/obfs4/client-windows/lib)
find_library(CGOLIB NAMES shapeshifter-obfs4-go.lib shapeshifter-obfs4-go HINTS lib)

target_link_libraries(shapeshifter_plugin_obfs4 wsock32 ws2_32 ${CGOLIB})