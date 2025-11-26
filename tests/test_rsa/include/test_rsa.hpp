#pragma once

#include "rsa.hpp"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <string>

class SimpleRSATests {
public:
    SimpleRSATests();
    ~SimpleRSATests();

    bool run_all_tests();

    bool test_text_files();
    bool test_binary_files();
    bool test_pdf_files();
    bool test_zip_files();
    bool test_mp4_files();
    bool test_jpg_files();
    bool test_different_key_sizes();
    bool test_error_handling();
    void print_stats() const;

private:
    bool compare_files(const std::filesystem::path& file1, const std::filesystem::path& file2);

    std::filesystem::path test_dir;
    std::filesystem::path test_files_dir;

    int tests_passed;
    int tests_failed;
    int total_tests;
};