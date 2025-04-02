cmake_minimum_required(VERSION 3.18)
project(ldacs_test C)

set(CMAKE_C_STANDARD 11)


set(tests
        snpsub
)

cmake_host_system_information(RESULT PRETTY_NAME QUERY DISTRIB_PRETTY_NAME)
IF (${PRETTY_NAME} MATCHES "Ubuntu")
    #    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -g")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=leak -g")
ENDIF ()
INCLUDE_DIRECTORIES(/usr/local/include/ldacs)

enable_testing()
foreach (name ${tests})
    add_test(NAME ${name} COMMAND ${name}test)
    add_executable(${name}test ${name}_test.c)
    target_link_libraries(${name}test LINK_PUBLIC ldcauc base64)
    target_include_directories(${name}test PUBLIC ${CMAKE_SOURCE_DIR}/include)


    #    cmake_host_system_information(RESULT PRETTY_NAME QUERY DISTRIB_PRETTY_NAME)
    #    IF (${PRETTY_NAME} MATCHES "Ubuntu")
    #        target_link_libraries(${name}test LINK_PUBLIC gmssl)
    #        target_compile_definitions(${name}test PRIVATE UNUSE_CRYCARD)
    #    ELSEIF (${PRETTY_NAME} MATCHES "CentOS")
    #        target_link_libraries(${name}test LINK_PUBLIC km_src uuid)
    #        target_compile_definitions(${name}test PRIVATE USE_CRYCARD)
    #    ENDIF ()
    find_package(Ldacsutils REQUIRED)

    if (Ldacsutils_FOUND)
        target_include_directories(${name}test PUBLIC ${Ldacsutils_INCLUDE_DIRS})
        target_link_libraries(${name}test PUBLIC ldacsutils::ldacsutils)
    endif ()
endforeach ()

