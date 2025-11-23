add_library(test_rsa src/test_rsa.cpp)
target_link_libraries(test_rsa PRIVATE rsa bits_functions number_functions primality_tests Boost::random Boost::system)
target_include_directories(test_rsa PUBLIC include)