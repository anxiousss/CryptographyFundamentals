#include "test_serpent.hpp"

int main() {
    TestRunner runner;

    SerpentTest serpent_test(runner);
    serpent_test.run_all_tests();

    TestFileConfig config;
    config.set_custom_files(
            "test_files/test.txt",
            "test_files/test.bin",
            "test_files/SMILEFACE.jpg",
            "test_files/test.pdf",
            "test_files/test.zip",
            "test_files/test.mp4"
    );


    if (config.has_any_files()) {
        test_serpent_file_operations(runner, config);
    } else {
        std::cout << "\nNo test files provided. Skipping file operations tests." << std::endl;
        std::cout << "To test file operations, set file paths in TestFileConfig." << std::endl;
    }

    runner.print_summary();

    return runner.tests_failed == 0 ? 0 : 1;
}