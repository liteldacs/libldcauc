cmake_minimum_required(VERSION 3.20)
project(ldcauc VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)

#设置默认的安装位置
if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "/usr/local/ldacs-cauc" CACHE PATH "Default install path" FORCE)
endif ()

message(${CMAKE_INSTALL_PREFIX})

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

option(SGW_DEVICE "SGW Device Option" OFF)
option(AS_DEVICE "AS Device Option" OFF)
option(GS_DEVICE "GS Device Option" OFF)

IF (SGW_DEVICE)
    MESSAGE(STATUS "SGW Device Compiling...")
    target_link_libraries(${PROJECT_NAME} LINK_PUBLIC sdf)
    target_compile_definitions(${PROJECT_NAME} PRIVATE USE_CRYCARD)
ELSEIF (AS_DEVICE OR GS_DEVICE)
    MESSAGE(STATUS "AS/GS Device Compiling...")
    target_link_libraries(${PROJECT_NAME} LINK_PUBLIC piico_ccmu)
    #    option(USE_PIICO "Enable PIICO" ON)
    target_compile_definitions(${PROJECT_NAME} PRIVATE USE_CRYCARD)
ELSE ()
    MESSAGE(STATUS "Using GMSSL...")
    target_link_libraries(${PROJECT_NAME} LINK_PUBLIC gmssl)
    #    option(USE_GMSSL "Enable GMSSL" ON)
    target_compile_definitions(${PROJECT_NAME} PRIVATE UNUSE_CRYCARD)
ENDIF ()

find_package(LiteLdacsSdk REQUIRED)
if (LiteLdacsSdk_FOUND)
    include_directories(${LiteLdacsSdk_INCLUDE_DIRS})
    include_directories(${LiteLdacsSdk_INCLUDE_GLOBAL_DIRS})
    link_libraries(liteldacssdk::liteldacssdk)
endif ()


find_package(Ldacscrypto REQUIRED)
if (Ldacscrypto_FOUND)
    target_include_directories(${PROJECT_NAME} PUBLIC ${Ldacscrypto_INCLUDE_DIRS})
    target_link_libraries(${PROJECT_NAME} PUBLIC ldacscrypto::ldacscrypto)
endif ()


SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES output_name "ldcauc")
SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)
INSTALL(TARGETS ${PROJECT_NAME} EXPORT LdcaucTargets ARCHIVE DESTINATION lib LIBRARY DESTINATION lib)
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

message(${CMAKE_INSTALL_PREFIX})
INSTALL(CODE "
    # 创建目录（包含父目录）
    file(MAKE_DIRECTORY \"\$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/log\")
    # 设置目录权限：所有者读写执行，组和其他人读执行
    file(CHMOD \"\$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}\"
        DIRECTORY_PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE
    )
    file(CHMOD \"\$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/log\"
        DIRECTORY_PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE GROUP_WRITE
        WORLD_READ WORLD_EXECUTE WORLD_WRITE
    )

    file(COPY \"${CMAKE_SOURCE_DIR}/config\"
    DESTINATION \"\$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}\"
    FILE_PERMISSIONS
        OWNER_READ OWNER_WRITE
        GROUP_READ
        WORLD_READ
    )
    file(CHMOD \"\$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/config\"
        DIRECTORY_PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE
    )
")