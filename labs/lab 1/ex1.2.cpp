#include "test_triple_des.hpp"

int main() {
    run_all_tripledes_tests_with_custom_files(
            "test_files/test.txt",
            "test_files/test.bin",
            "test_files/SMILEFACE.jpg",
            "test_files/test.pdf",
            "test_files/test.zip",
            "test_files/test.mp4");

    return 0;
}