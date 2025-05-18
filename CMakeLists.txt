cmake_minimum_required(VERSION 3.15)
project(lab4_network)

set(CMAKE_CXX_STANDARD 17)
include_directories(${CMAKE_SOURCE_DIR}/include)

add_executable(server src/server.cpp)
target_link_libraries(server pthread)       # для fork/sigaction не нужно, но на всякий случай
add_executable(client src/client.cpp)
