add_library(rijndael SHARED src/rijndael.cpp include/rijndael.hpp )
target_link_libraries(rijndael PUBLIC bits_functions symmetric_context galois_fields)
target_include_directories(rijndael PUBLIC include)