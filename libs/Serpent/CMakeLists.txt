add_library(serpent SHARED src/serpent.cpp)
target_link_libraries(serpent PUBLIC bits_functions symmetric_context)
target_include_directories(serpent PUBLIC include)