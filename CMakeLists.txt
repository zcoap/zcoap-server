cmake_minimum_required(VERSION 3.0.0)
project(zcoap-server VERSION 0.1.0)

include(CTest)
enable_testing()

message(STATUS "\r\n********************************************\r\n-- zcoap-server cmake - entry")

#Print important settings
message(STATUS "TOOLCHAIN = ${CMAKE_TOOLCHAIN_FILE}")
message(STATUS "CMAKE_MODULE_PATH = ${CMAKE_MODULE_PATH}")

add_library(zcoap-server
            src/config.h
            src/platform.h
            src/zcoap-server.c
            src/zcoap-server.h
            src/zsnprintf.c
            src/zsnprintf.h)

target_link_libraries(zcoap-server
                      m)

IF (WIN32)

add_executable(example-server-win32
               examples/example-server-win32.c)

ELSE()

add_executable(example-server-linux
               examples/example-server-linux.c)

target_link_libraries(example-server-linux
                      zcoap-server)

ENDIF()

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})

include(CPack)
