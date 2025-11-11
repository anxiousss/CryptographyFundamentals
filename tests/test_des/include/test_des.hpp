#pragma once

#include <iostream>
#include <vector>
#include <cassert>
#include <string>
#include <memory>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include "symmetric_context.hpp"
#include "des.hpp"

using namespace symmetric_context;

class TestRunner {
private:
    int tests_passed = 0;
    std::string current_test;

public:
    int tests_failed = 0;
    void start_test(const std::string& test_name);
    void end_test(bool passed);

    template<typename T>
    void assert_equal(const T& actual, const T& expected, const std::string& message = "") {
        if (actual != expected) {
            std::cout << "FAILED - " << message
                      << " [Expected: " << expected << ", Got: " << actual << "]" << std::endl;
            end_test(false);
            throw std::runtime_error("Assertion failed");
        }
    }

    void assert_true(bool condition, const std::string& message = "") {
        if (!condition) {
            std::cout << "FAILED - " << message << std::endl;
            end_test(false);
            throw std::runtime_error("Assertion failed");
        }
    }

    void print_summary();
};

bool compare_byte_vectors(const std::vector<std::byte>& v1, const std::vector<std::byte>& v2);
bool compare_files(const std::filesystem::path& file1, const std::filesystem::path& file2);
void print_file_metrics(const std::string& description,
                        uint64_t original_size,
                        uint64_t encrypted_size,
                        uint64_t decrypted_size,
                        const std::chrono::milliseconds& encrypt_time,
                        const std::chrono::milliseconds& decrypt_time);

std::unique_ptr<des::DES> create_des_algorithm(const std::vector<std::byte>& key);

// Конфигурация тестов - здесь вы можете задать свои файлы
namespace test_config_des {
    extern std::filesystem::path text_file_path;
    extern std::filesystem::path binary_file_path;
    extern std::filesystem::path image_file_path;
    extern std::filesystem::path pdf_file_path;
    extern std::filesystem::path zip_file_path;
    extern std::filesystem::path mp4_file_path;

    void set_custom_files(
            const std::filesystem::path& text_file = "",
            const std::filesystem::path& binary_file = "",
            const std::filesystem::path& image_file = "",
            const std::filesystem::path& pdf_file = "",
            const std::filesystem::path& zip_file = "",
            const std::filesystem::path& mp4_file = ""
    );
}

// Базовые тесты DES
void test_ecb_encryption_decryption_des(TestRunner& runner);
void test_cbc_encryption_decryption_des(TestRunner& runner);
void test_pcbc_encryption_decryption_des(TestRunner& runner);
void test_cfb_encryption_decryption_des(TestRunner& runner);
void test_ofb_encryption_decryption_des(TestRunner& runner);
void test_ctr_encryption_decryption_des(TestRunner& runner);
void test_random_delta_encryption_decryption_des(TestRunner& runner);
void test_different_padding_modes_des(TestRunner& runner);
void test_empty_data_des(TestRunner& runner);
void test_large_data_des(TestRunner& runner);
void test_thread_safety_des(TestRunner& runner);

// Тесты файлов с измерением времени и размеров
void test_text_file_operations_des(TestRunner& runner);
void test_binary_file_operations_des(TestRunner& runner);
void test_image_file_operations_des(TestRunner& runner);
void test_pdf_file_operations_des(TestRunner& runner);
void test_zip_file_operations_des(TestRunner& runner);
void test_mp4_file_operations_des(TestRunner& runner);

int run_all_des_tests();
void run_all_des_tests_with_custom_files(
        const std::filesystem::path& text_file = "",
        const std::filesystem::path& binary_file = "",
        const std::filesystem::path& image_file = "",
        const std::filesystem::path& pdf_file = "",
        const std::filesystem::path& zip_file = "",
        const std::filesystem::path& mp4_file = ""
);