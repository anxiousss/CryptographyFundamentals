cmake_minimum_required(VERSION 3.22.1)
project(CryptographyFundamentals)

set(CMAKE_CXX_STANDARD 20)
# Disable C++ modules TS to fix dependency scanning issues
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

add_subdirectory(libs/bits_functions)
add_subdirectory(libs/SymmetricContext)
add_subdirectory(libs/FeistelNetwork)
add_subdirectory(libs/DES)
add_subdirectory(tests/test_bits_functions)
add_subdirectory(tests/test_symmetric_context)


add_executable(lab1t1 "lab 1/ex1.cpp")
add_executable(lab1t2-t5 "lab 1/ex2.cpp")

target_link_libraries(lab1t1 test_bits_functions bits_functions)
target_link_libraries(lab1t2-t5 test_symmetric_context symmetric_context feistel_network des)