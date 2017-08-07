cmake_minimum_required(VERSION 3.3)
project(reload)

set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -rdynamic")

add_library(reloader SHARED lib.c)

add_executable(reload test.c reload/plthook.h reload/plthook_elf.c)
target_link_libraries(reload dl reloader m)