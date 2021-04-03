cmake_minimum_required(VERSION 3.0.0)
project(zcoap-server VERSION 0.1.0)

include(CTest)
enable_testing()

message(STATUS "\r\n********************************************\r\n-- zcoap-server cmake - entry")

#Print important settings as needed
message(STATUS "TOOLCHAIN = ${CMAKE_TOOLCHAIN_FILE}")
message(STATUS "CMAKE_MODULE_PATH = ${CMAKE_MODULE_PATH}")

#Include the platform specific platform.h which config.h depends on. 
#Use platform.h to define environment-specific things


#------------------------------------------------------------------------------
#First define some include directories  and compile flags based on the platform
#we are compiling against

#Windows
IF (WIN32)

include_directories(examples/win32 src)

ELSE()

#Linux
include_directories(examples/posix src)

#set(CMAKE_CXX_FLAGS "-Werror -Wshadow")
#set(CMAKE_C_FLAGS "-Werror -Wshadow")

ENDIF()

#------------------------------------------------------------------------------
#This is the primary library which your application can link against
add_library(zcoap-server
            src/config.h
            src/zcoap-server.c
            src/zcoap-server.h
            lib/zsnprintf/zsnprintf.c
            lib/zsnprintf/zsnprintf.h)

#------------------------------------------------------------------------------
#Set properties for executable targets based on platform
IF (WIN32)

#Example application for win32
#Just open this CMakeLists.txt file in Visual Studio (ensure you have Linux tools installed for VS as well)
add_executable(example-server-win32
               examples/win32/platform.h
               examples/win32/server-win32.c
               examples/win32/server-win32-endpoints.c
               examples/win32/server-win32-endpoints.h)

#Link this application against zcoap-server
target_link_libraries(example-server-win32
                      zcoap-server)

ELSE()

#Example program for Posix platforms
add_executable(example-server-posix
               examples/posix/platform.h
               examples/posix/server.c
               examples/posix/public.h
               examples/posix/public.c
               examples/posix/private.h
               examples/posix/private.c
               examples/posix/fs.h
               examples/posix/fs.c)

find_package (Threads)
target_link_libraries(example-server-posix
                      zcoap-server
                      ${CMAKE_THREAD_LIBS_INIT}
                      m)
target_compile_options(example-server-posix PRIVATE -Werror -Wshadow)

ENDIF()

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})

include(CPack)

