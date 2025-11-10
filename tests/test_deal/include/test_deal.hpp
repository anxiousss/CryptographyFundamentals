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
#include "deal.hpp"

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

std::unique_ptr<deal::DEAL> create_deal_algorithm_128(const std::vector<std::byte>& key);
std::unique_ptr<deal::DEAL> create_deal_algorithm_192(const std::vector<std::byte>& key);
std::unique_ptr<deal::DEAL> create_deal_algorithm_256(const std::vector<std::byte>& key);

// Конфигурация тестов - здесь вы можете задать свои файлы
namespace test_config {
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

// Базовые тесты DEAL-128
void test_ecb_encryption_decryption_deal(TestRunner& runner);
void test_cbc_encryption_decryption_deal(TestRunner& runner);
void test_pcbc_encryption_decryption_deal(TestRunner& runner);
void test_cfb_encryption_decryption_deal(TestRunner& runner);
void test_ofb_encryption_decryption_deal(TestRunner& runner);
void test_ctr_encryption_decryption_deal(TestRunner& runner);
void test_random_delta_encryption_decryption_deal(TestRunner& runner);
void test_different_padding_modes_deal(TestRunner& runner);
void test_empty_data_deal(TestRunner& runner);
void test_large_data_deal(TestRunner& runner);
void test_thread_safety_deal(TestRunner& runner);

// Тесты файлов с измерением времени и размеров
void test_text_file_operations_deal(TestRunner& runner);
void test_binary_file_operations_deal(TestRunner& runner);
void test_image_file_operations_deal(TestRunner& runner);
void test_pdf_file_operations_deal(TestRunner& runner);
void test_zip_file_operations_deal(TestRunner& runner);
void test_mp4_file_operations_deal(TestRunner& runner);

// Тесты для DEAL-192
void test_ecb_deal_192(TestRunner& runner);
void test_cbc_deal_192(TestRunner& runner);
void test_pcbc_deal_192(TestRunner& runner);
void test_cfb_deal_192(TestRunner& runner);
void test_ofb_deal_192(TestRunner& runner);
void test_ctr_deal_192(TestRunner& runner);
void test_random_delta_deal_192(TestRunner& runner);

// Тесты для DEAL-256
void test_ecb_deal_256(TestRunner& runner);
void test_cbc_deal_256(TestRunner& runner);
void test_pcbc_deal_256(TestRunner& runner);
void test_cfb_deal_256(TestRunner& runner);
void test_ofb_deal_256(TestRunner& runner);
void test_ctr_deal_256(TestRunner& runner);
void test_random_delta_deal_256(TestRunner& runner);

// Комплексные тесты
void test_large_data_deal_192(TestRunner& runner);
void test_large_data_deal_256(TestRunner& runner);
void test_different_padding_modes_deal_192(TestRunner& runner);
void test_different_padding_modes_deal_256(TestRunner& runner);
void test_file_operations_deal_192(TestRunner& runner);
void test_file_operations_deal_256(TestRunner& runner);

int run_all_deal_tests();
void run_all_deal_tests_with_custom_files(
        const std::filesystem::path& text_file = "",
        const std::filesystem::path& binary_file = "",
        const std::filesystem::path& image_file = "",
        const std::filesystem::path& pdf_file = "",
        const std::filesystem::path& zip_file = "",
        const std::filesystem::path& mp4_file = ""
);