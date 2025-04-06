cmake_minimum_required(VERSION 3.18)
project(ldcauc VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)

#设置默认的安装位置
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "/usr/local/ldacs-cauc" CACHE PATH "Default install path" FORCE)
endif()

#AUX_SOURCE_DIRECTORY(. SRC_LIST) #把当前目录(.)下所有源代码文件和头文件加入变量SRC_LIST
file(GLOB_RECURSE SOURCES "*.c")
add_library(${PROJECT_NAME} STATIC ${SOURCES})

#target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/include)

target_include_directories(${PROJECT_NAME}
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_PREFIX}/include/ldcauc>
)

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


SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES output_name "ldcauc")
SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)
INSTALL(TARGETS ${PROJECT_NAME} EXPORT LdcaucTargets ARCHIVE DESTINATION lib LIBRARY DESTINATION lib )
INSTALL(DIRECTORY ${CMAKE_SOURCE_DIR}/include/ DESTINATION include/ldcauc)

INSTALL(EXPORT LdcaucTargets
        FILE LdcaucTargets.cmake
        NAMESPACE ldcauc::
        DESTINATION /usr/local/lib/cmake/ldcauc
)

# 生成并安装 Config 文件
include(CMakePackageConfigHelpers)

# 生成 aaaConfigVersion.cmake
write_basic_package_version_file(
        ${CMAKE_SOURCE_DIR}/cmake/LdcaucConfigVersion.cmake
        VERSION ${Ldcauc_VERSION}
        COMPATIBILITY SameMajorVersion
)

# 生成 aaaConfig.cmake
configure_package_config_file(
        ${CMAKE_SOURCE_DIR}/cmake/LdcaucConfig.cmake.in
        ${CMAKE_SOURCE_DIR}/cmake/LdcaucConfig.cmake
        INSTALL_DESTINATION /usr/local/lib/cmake/ldcauc
)

# 安装 Config 和 Targets 文件
install(
        FILES
        ${CMAKE_SOURCE_DIR}/cmake/LdcaucConfig.cmake
        ${CMAKE_SOURCE_DIR}/cmake/LdcaucConfigVersion.cmake
        DESTINATION /usr/local/lib/cmake/ldcauc
)

message("${CMAKE_INSTALL_PREFIX}")

set(SO_PATH /usr/local/ldacs-cauc/lib)
set(SO_CONFIG_DIR /etc/ld.so.conf.d)

INSTALL(CODE "execute_process(COMMAND sudo sh -c \"echo ${SO_PATH} > ${SO_CONFIG_DIR}/ldacs-cauc.conf\" COMMAND sudo ldconfig )")
