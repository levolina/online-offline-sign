cmake_minimum_required(VERSION 3.11)

project(oosign)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/Modules")

enable_testing()

add_subdirectory(src)
add_subdirectory(test)