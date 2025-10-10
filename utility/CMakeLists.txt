cmake_minimum_required(VERSION 3.10)
project(utility)

add_library(utility src/utility.cpp)
target_include_directories(utility PUBLIC include)