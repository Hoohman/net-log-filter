cmake_minimum_required(VERSION 3.20)
project(NetworkLogFilter LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Core
add_library(log_filter_lib STATIC
    src/log_filter.cpp
)
target_include_directories(log_filter_lib PUBLIC include)

# Demo application
add_executable(NetworkLogFilter src/main.cpp)
target_link_libraries(NetworkLogFilter PRIVATE log_filter_lib)

# Tests
add_executable(NetworkLogFilterTests tests/test_filter.cpp)
target_link_libraries(NetworkLogFilterTests PRIVATE log_filter_lib)