#pragma once

#include "test_utility.hpp"
#include "triple_des.hpp"

class TripleDESTest : public AlgorithmTestBase {
private:
    static std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_tripledes_algorithm_ede(const std::vector<std::byte>& key);
    static std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_tripledes_algorithm_eee(const std::vector<std::byte>& key);

public:
    explicit TripleDESTest(TestRunner& runner_ref) : AlgorithmTestBase(runner_ref) {}

    void run_all_tests(const TestFileConfig& config = {});

private:
    std::vector<std::byte> get_default_key() const;
    std::vector<std::byte> get_default_iv() const;

    void test_thread_safety();
    void test_performance();
    void test_single_block_operations();

protected:
    symmetric_context::EncryptionModes get_file_encryption_mode() const override;
    symmetric_context::PaddingModes get_file_padding_mode() const override;
};

int run_all_tripledes_tests();
void run_all_tripledes_tests_with_custom_files(
        const std::filesystem::path& text_file = "",
        const std::filesystem::path& binary_file = "",
        const std::filesystem::path& image_file = "",
        const std::filesystem::path& pdf_file = "",
        const std::filesystem::path& zip_file = "",
        const std::filesystem::path& mp4_file = ""
);