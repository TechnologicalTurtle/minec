cmake_minimum_required(VERSION 3.23)

project(Client)

add_executable(Client)

set_target_properties(Client PROPERTIES
        CXX_STANDARD 20
        CMAKE_CXX_STANDARD_REQUIRED ON
)

find_package(ZLIB)
target_link_libraries(Client
    minec
    ssl
    crypto
    ZLIB::ZLIB
)

target_sources(Client
    PRIVATE
        main.cpp
)