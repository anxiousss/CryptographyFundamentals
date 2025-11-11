#include "test_des.hpp"

int main() {
    run_all_des_tests_with_custom_files(
            "test.txt",
            "test.bin",
            "SMILEFACE.jpg",
            "test.pdf",
            "test.zip",
            "test.mp4"
    );
    return 0;
}