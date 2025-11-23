// simple_rsa_tests.h
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

    // Основные тесты
    bool run_all_tests();

    // Индивидуальные тесты
    bool test_text_files();
    bool test_binary_files();
    bool test_pdf_files();
    bool test_zip_files();
    bool test_mp4_files();
    bool test_jpg_files();
    bool test_different_key_sizes();
    bool test_auto_generated_filenames();
    bool test_error_handling();

    // Статистика
    void print_stats() const;

private:
    // Вспомогательные методы
    bool compare_files(const std::filesystem::path& file1, const std::filesystem::path& file2);
    std::filesystem::path create_test_dir();
    void cleanup();

    // Тестовые директории
    std::filesystem::path test_dir;
    std::filesystem::path test_files_dir;

    // Статистика
    int tests_passed;
    int tests_failed;
    int total_tests;
};