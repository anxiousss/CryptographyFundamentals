add_library(primality_tests src/primality_tests.cpp include/primality_tests.hpp)
target_link_libraries(primality_tests PUBLIC number_functions Boost::random Boost::system)
target_include_directories(primality_tests PUBLIC include)