cmake_minimum_required(VERSION 3.18)
project(libldcauc C)

set(CMAKE_C_STANDARD 11)

add_subdirectory(src)
add_subdirectory(tests)

INSTALL(DIRECTORY ${CMAKE_SOURCE_DIR}/global/ DESTINATION include/ldacs/global)
