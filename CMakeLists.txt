cmake_minimum_required(VERSION 3.22.1)
project(CryptographyFundamentals)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)


# find_package(Boost REQUIRED COMPONENTS filesystem random system)

add_compile_options(-O3)

add_subdirectory(libs/bits_functions)
add_subdirectory(libs/SymmetricContext)
add_subdirectory(libs/FeistelNetwork)
add_subdirectory(libs/DES)
add_subdirectory(libs/DEAL)
add_subdirectory(libs/NumberFunctions)
add_subdirectory(libs/PrimalityTests)
add_subdirectory(tests/test_bits_functions)
add_subdirectory(tests/test_des)
add_subdirectory(tests/test_deal)

add_executable(lab1t1 "labs/lab 1/ex1.cpp")
add_executable(lab1t2-t5 "labs/lab 1/ex2-5.cpp")
add_executable(lab1t6-t7 "labs/lab 1/ex6-7.cpp")
add_executable(lab2t1-t2 "labs/lab 2/ex1-2.cpp")

target_link_libraries(lab1t1 test_bits_functions bits_functions)
target_link_libraries(lab1t2-t5 test_des symmetric_context feistel_network des)
target_link_libraries(lab1t6-t7 test_deal symmetric_context feistel_network des deal)
target_link_libraries(lab2t1-t2 number_functions primality_tests)