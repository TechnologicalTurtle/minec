cmake_minimum_required(VERSION 3.23)

project(minec)
add_library(minec)

set_target_properties(minec PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED ON.
)

find_package(ZLIB)
target_link_libraries(minec
        ssl
        crypto
        ZLIB::ZLIB
)

target_sources(minec
    PRIVATE
        old_src/minec.cpp
    PUBLIC
    FILE_SET headers
    TYPE HEADERS
    FILES
        old_include/minec.hpp
)