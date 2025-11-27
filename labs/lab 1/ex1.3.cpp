#include "test_deal.hpp"

int main() {
    run_all_deal_tests_with_custom_files(
            "test_files/test.txt",
            "test_files/test.bin",
            "test_files/SMILEFACE.jpg",
            "test_files/test.pdf",
            "test_files/test.zip",
            "test_files/test.mp4");

    return 0;
}