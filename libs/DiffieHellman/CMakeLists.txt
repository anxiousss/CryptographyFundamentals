add_library(diffie_hellman SHARED src/diffie_hellman.cpp)
target_link_libraries(diffie_hellman PUBLIC number_functions primality_tests Boost::system Boost::random)
target_include_directories(diffie_hellman PUBLIC include)