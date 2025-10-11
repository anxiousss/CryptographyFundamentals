cmake_minimum_required(VERSION 4.0)
project(CryptographyFundamentals)

set(CMAKE_CXX_STANDARD 20)
# Disable C++ modules TS to fix dependency scanning issues
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

add_subdirectory(utility)

add_executable(lab1t1 "lab 1/ex1.cpp")
add_executable(lab1t2 "lab 1/ex2.cpp")

target_link_libraries(lab1t1 utility)
target_link_libraries(lab1t2 utility)