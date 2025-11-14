add_library(rsa src/rsa.cpp)
target_link_libraries(rsa PUBLIC number_functions primality_tests Boost::random Boost::system)
target_include_directories(rsa PUBLIC include)