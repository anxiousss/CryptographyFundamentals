add_library(rsa src/rsa.cpp)
target_link_libraries(rsa PUBLIC bits_functions number_functions primality_tests Boost::random Boost::system OpenSSL::SSL OpenSSL::Crypto)
target_include_directories(rsa PUBLIC include)