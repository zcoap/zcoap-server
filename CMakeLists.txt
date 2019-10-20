cmake_minimum_required(VERSION 3.0.0)
project(zcoap-server VERSION 0.1.0)

include(CTest)
enable_testing()

message(STATUS "\r\n********************************************\r\n-- zcoap-server cmake - entry")

#Print important settings as needed
message(STATUS "TOOLCHAIN = ${CMAKE_TOOLCHAIN_FILE}")
message(STATUS "CMAKE_MODULE_PATH = ${CMAKE_MODULE_PATH}")

add_library(zcoap-server
            src/config.h
            src/zcoap-server.c
            src/zcoap-server.h
            src/zsnprintf.c
            src/zsnprintf.h)

IF (WIN32)

add_executable(example-server-win32
               example-win32/platform.h
               example-win32/server-win32.c
               example-win32/server-win32-endpoints.c
               example-win32/server-win32-endpoints.h)

ELSE()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}" "-Werror -Wshadow")

add_executable(example-server-linux
               example-linux/platform.h
               example-linux/server-linux.c
               example-linux/server-linux-fs.c
               example-linux/server-linux-fs.h
               example-linux/server-linux-telemetry.c
               example-linux/server-linux-telemetry.h)

target_link_libraries(example-server-linux
                      zcoap-server
                      m)


ENDIF()

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})

include(CPack)

