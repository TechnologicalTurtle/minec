cmake_minimum_required(VERSION 3.23)

project(minec)
add_library(minec)

set_target_properties(minec PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED ON.
)

target_link_libraries(minec
        ssl
        crypto
)

target_sources(minec
    PRIVATE
        src/minec.cpp
    PUBLIC
    FILE_SET headers
    TYPE HEADERS
    FILES
        include/minec.hpp
)