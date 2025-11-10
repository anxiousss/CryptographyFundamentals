#include "test_deal.hpp"

int main() {
    run_all_deal_tests_with_custom_files(
            "test.txt",
            "test.bin",
            "SMILEFACE.jpg",
            "test.pdf",
            "test.zip",
            "test.mp4"
    );
    return 0;
}