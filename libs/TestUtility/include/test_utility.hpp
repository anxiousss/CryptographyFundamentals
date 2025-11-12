#pragma once

#include <iostream>
#include <vector>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <fstream>
#include <cassert>

#include "symmetric_context.hpp"

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

struct TestFileConfig {
    std::filesystem::path text_file_path = "";
    std::filesystem::path binary_file_path = "";
    std::filesystem::path image_file_path = "";
    std::filesystem::path pdf_file_path = "";
    std::filesystem::path zip_file_path = "";
    std::filesystem::path mp4_file_path = "";

    void set_custom_files(
            const std::filesystem::path& text_file = "",
            const std::filesystem::path& binary_file = "",
            const std::filesystem::path& image_file = "",
            const std::filesystem::path& pdf_file = "",
            const std::filesystem::path& zip_file = "",
            const std::filesystem::path& mp4_file = ""
    );

    bool has_any_files() const {
        return !text_file_path.empty() || !binary_file_path.empty() ||
               !image_file_path.empty() || !pdf_file_path.empty() ||
               !zip_file_path.empty() || !mp4_file_path.empty();
    }

    void print_available_files() const;
};

namespace test_utils {
    std::filesystem::path setup_test_directory(const std::string& algorithm_name);
    bool test_single_file_operation(
            TestRunner& runner,
            const std::string& file_type,
            const std::filesystem::path& file_path,
            const std::vector<std::byte>& key,
            const std::vector<std::byte>& iv,
            std::unique_ptr<symmetric_context::SymmetricAlgorithm> algorithm,
            symmetric_context::EncryptionModes encryption_mode,
            symmetric_context::PaddingModes padding_mode,
            const std::string& algorithm_name
    );
}

class AlgorithmTestBase {
protected:
    TestRunner& runner;

public:
    explicit AlgorithmTestBase(TestRunner& runner_ref) : runner(runner_ref) {}

    virtual ~AlgorithmTestBase() = default;

    void test_basic_encryption_modes(
            const std::vector<std::byte>& key,
            const std::vector<std::byte>& iv,
            std::unique_ptr<symmetric_context::SymmetricAlgorithm> (*create_algorithm)(const std::vector<std::byte>&),
            const std::string& algorithm_name
    );

    void test_file_operations(
            const std::vector<std::byte>& key,
            const std::vector<std::byte>& iv,
            std::unique_ptr<symmetric_context::SymmetricAlgorithm> (*create_algorithm)(const std::vector<std::byte>&),
            const TestFileConfig& config,
            const std::string& algorithm_name
    );

    void test_padding_modes(
            const std::vector<std::byte>& key,
            const std::vector<std::byte>& iv,
            std::unique_ptr<symmetric_context::SymmetricAlgorithm> (*create_algorithm)(const std::vector<std::byte>&)
    );

    void test_edge_cases(
            const std::vector<std::byte>& key,
            std::unique_ptr<symmetric_context::SymmetricAlgorithm> (*create_algorithm)(const std::vector<std::byte>&)
    );

protected:
    virtual symmetric_context::EncryptionModes get_file_encryption_mode() const {
        return symmetric_context::EncryptionModes::CBC;
    }

    virtual symmetric_context::PaddingModes get_file_padding_mode() const {
        return symmetric_context::PaddingModes::PKCS7;
    }
};