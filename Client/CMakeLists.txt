cmake_minimum_required(VERSION 3.23)

project(Client)

add_executable(Client)

set_target_properties(Client PROPERTIES
        CXX_STANDARD 20
        CMAKE_CXX_STANDARD_REQUIRED ON
)

target_link_libraries(Client
    minec
)

target_sources(Client
    PRIVATE
        old_main.cpp
)