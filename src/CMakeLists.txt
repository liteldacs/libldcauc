cmake_minimum_required(VERSION 3.18)
project(ldcauc)

set(CMAKE_C_STANDARD 11)

#AUX_SOURCE_DIRECTORY(. SRC_LIST) #把当前目录(.)下所有源代码文件和头文件加入变量SRC_LIST
file(GLOB_RECURSE SOURCES "*.c")
add_library(${PROJECT_NAME} STATIC ${SOURCES})

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(${PROJECT_NAME} LINK_PUBLIC pthread)

cmake_host_system_information(RESULT PRETTY_NAME QUERY DISTRIB_PRETTY_NAME)
cmake_host_system_information(RESULT HOST_NAME QUERY HOSTNAME)
IF (${HOST_NAME} MATCHES "gateway" OR ${HOST_NAME} MATCHES "gsc")
    target_link_libraries(${PROJECT_NAME} LINK_PUBLIC km_src sdf)
    target_compile_definitions(${PROJECT_NAME} PRIVATE USE_CRYCARD)
ELSEIF (${HOST_NAME} MATCHES "gs" OR ${HOST_NAME} MATCHES "as")
    target_link_libraries(${PROJECT_NAME} LINK_PUBLIC km_src piico_ccmu)
    target_compile_definitions(${PROJECT_NAME} PRIVATE USE_CRYCARD)
ELSE ()
    target_link_libraries(${PROJECT_NAME} LINK_PUBLIC km_src gmssl)
    target_compile_definitions(${PROJECT_NAME} PRIVATE UNUSE_CRYCARD)
ENDIF ()

find_package(Ldacsutils REQUIRED)
if (Ldacsutils_FOUND)
    target_include_directories(${PROJECT_NAME} PUBLIC ${Ldacsutils_INCLUDE_DIRS})
    target_link_libraries(${PROJECT_NAME} PUBLIC ldacsutils::ldacsutils base64)
endif ()

find_package(Ldacscrypto REQUIRED)
if (Ldacscrypto_FOUND)
    #    get_cmake_property(_variableNames VARIABLES)
    #    foreach (_variableName ${_variableNames})
    #        if (_variableName MATCHES "^Ldacscrypto")
    #            message(STATUS "${_variableName}=${${_variableName}}")
    #        endif ()
    #    endforeach ()
    target_include_directories(${PROJECT_NAME} PUBLIC ${Ldacscrypto_INCLUDE_DIRS})
    target_link_libraries(${PROJECT_NAME} PUBLIC ldacscrypto::ldacscrypto)
endif ()

SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES output_name "ldacs_util")
SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)
INSTALL(TARGETS ${PROJECT_NAME} ARCHIVE DESTINATION lib/ldacs LIBRARY DESTINATION lib/ldacs RUNTIME DESTINATION bin)
INSTALL(DIRECTORY ${CMAKE_SOURCE_DIR}/include/ DESTINATION include/ldacs/utils)
