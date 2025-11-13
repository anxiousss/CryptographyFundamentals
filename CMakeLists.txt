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
add_subdirectory(libs/TestUtility)
add_subdirectory(libs/TripleDes)
add_subdirectory(tests/test_des)
add_subdirectory(tests/test_deal)
add_subdirectory(tests/test_triple_des)

add_executable(lab1t1 "labs/lab 1/ex1.1.cpp")
add_executable(lab1t2 "labs/lab 1/ex1.2.cpp")
add_executable(lab1t3 "labs/lab 1/ex1.3.cpp")

target_link_libraries(lab1t1 test_utility test_des symmetric_context feistel_network des)
target_link_libraries(lab1t2 test_utility test_triple_des triple_des symmetric_context feistel_network des)
target_link_libraries(lab1t3 test_utility test_deal symmetric_context feistel_network des deal)
