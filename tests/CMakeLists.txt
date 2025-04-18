cmake_minimum_required(VERSION 3.18)
project(ldacs_test C)

set(CMAKE_C_STANDARD 11)


set(tests
        snf
)

INCLUDE_DIRECTORIES(/usr/local/include/ldacs)

enable_testing()
foreach (name ${tests})
    add_test(NAME ${name} COMMAND ${name}test)
    add_executable(${name}test ${name}_test.c)
    target_link_libraries(${name}test LINK_PUBLIC ldcauc base64)
    target_include_directories(${name}test PUBLIC ${CMAKE_SOURCE_DIR}/include)


    find_package(LiteLdacsSdk REQUIRED)
    if (LiteLdacsSdk_FOUND)
        include_directories(${LiteLdacsSdk_INCLUDE_DIRS})
        link_libraries(liteldacssdk::liteldacssdk)
    endif ()


endforeach ()

