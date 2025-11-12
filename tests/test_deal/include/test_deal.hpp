#pragma once

#include "test_utility.hpp"
#include "deal.hpp"

class DealTest : public AlgorithmTestBase {
private:
    size_t key_size_;

    static std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_deal_algorithm(const std::vector<std::byte>& key);

public:
    DealTest(TestRunner& runner_ref, size_t key_size)
            : AlgorithmTestBase(runner_ref), key_size_(key_size) {}

    void run_all_tests(const TestFileConfig& config = {});

private:
    std::vector<std::byte> get_key() const;
    std::vector<std::byte> get_iv() const;

    void test_thread_safety(const std::string& algorithm_name);
    void test_performance(const std::string& algorithm_name);
    void test_different_key_sizes();
    void test_large_block_operations(const std::string& algorithm_name);

protected:
    symmetric_context::EncryptionModes get_file_encryption_mode() const override;
    symmetric_context::PaddingModes get_file_padding_mode() const override;
};

int run_all_deal_tests();
void run_all_deal_tests_with_custom_files(
        const std::filesystem::path& text_file = "",
        const std::filesystem::path& binary_file = "",
        const std::filesystem::path& image_file = "",
        const std::filesystem::path& pdf_file = "",
        const std::filesystem::path& zip_file = "",
        const std::filesystem::path& mp4_file = ""
);