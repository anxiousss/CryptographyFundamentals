cmake_minimum_required(VERSION 3.22.1)
project(CryptographyFundamentals)

set(CMAKE_CXX_STANDARD 20)
# Disable C++ modules TS to fix dependency scanning issues
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

add_subdirectory(libs/bits_functions)
add_subdirectory(libs/SymmetricAlgorithm)
add_subdirectory(libs/FeistelNetwork)
add_subdirectory(libs/DES)
add_subdirectory(tests/test_bits_functions)
add_subdirectory(tests/test_symmetric_algorithms)


add_executable(lab1t1 "lab 1/ex1.cpp")
add_executable(lab1t2 "lab 1/ex2.cpp")

target_link_libraries(lab1t1 test_bits_functions bits_functions)
target_link_libraries(lab1t2 test_symmetric_algorithms symmetric_algorithm feistel_network des)