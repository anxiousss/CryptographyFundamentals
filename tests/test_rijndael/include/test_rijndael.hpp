#pragma once

#include <vector>
#include <memory>
#include "test_utility.hpp"
#include "rijndael.hpp"

std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_rijndael_128_128(const std::vector<std::byte>& key);
std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_rijndael_192_128(const std::vector<std::byte>& key);
std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_rijndael_256_128(const std::vector<std::byte>& key);
std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_rijndael_128_192(const std::vector<std::byte>& key);
std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_rijndael_192_192(const std::vector<std::byte>& key);
std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_rijndael_256_192(const std::vector<std::byte>& key);
std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_rijndael_128_256(const std::vector<std::byte>& key);
std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_rijndael_192_256(const std::vector<std::byte>& key);
std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_rijndael_256_256(const std::vector<std::byte>& key);

std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_aes_128(const std::vector<std::byte>& key);
std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_aes_192(const std::vector<std::byte>& key);
std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_aes_256(const std::vector<std::byte>& key);

class RijndaelTest : public AlgorithmTestBase {
public:
    explicit RijndaelTest(TestRunner& runner_ref) : AlgorithmTestBase(runner_ref) {}

    void run_all_rijndael_tests(const TestFileConfig& config);

    void test_aes_128(const TestFileConfig& config);
    void test_aes_192(const TestFileConfig& config);
    void test_aes_256(const TestFileConfig& config);
    void test_rijndael_192_block(const TestFileConfig& config);
    void test_rijndael_256_block(const TestFileConfig& config);

private:
    void initialize_galois_fields();
    std::filesystem::path setup_test_directory();
};

void run_all_rijndael_tests_with_custom_files(
        const std::filesystem::path& text_file = "",
        const std::filesystem::path& binary_file = "",
        const std::filesystem::path& image_file = "",
        const std::filesystem::path& pdf_file = "",
        const std::filesystem::path& zip_file = "",
        const std::filesystem::path& mp4_file = ""
);

void run_basic_rijndael_tests();