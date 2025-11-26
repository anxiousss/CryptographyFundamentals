add_library(aes src/aes.cpp)
target_link_libraries(aes PUBLIC bits_functions symmetric_context sp_network)
target_include_directories(aes PUBLIC include)