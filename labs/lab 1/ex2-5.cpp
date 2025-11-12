#include "test_des.hpp"

int main() {

    run_all_des_tests_with_custom_files(
            "test_files/test.txt",
            "test_files/test.bin",
            "test_files/SMILEFACE.jpg",
            "test_files/test.pdf",
            "test_files/test.zip",
            "test_files/test2.mp4");

    return 0;
}