add_library(rc4 SHARED src/rc4.cpp)
target_link_libraries(rc4 PUBLIC bits_functions)
target_include_directories(rc4 PUBLIC include)