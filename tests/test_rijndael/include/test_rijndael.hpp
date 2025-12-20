#pragma once

#include <vector>
#include <memory>
#include <functional>
#include "test_utility.hpp"
#include "rijndael.hpp"

struct PolynomialConfig {
    std::byte polynomial;
    size_t index;
    std::string name;
};

std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_rijndael_with_polynomial(
        const std::vector<std::byte>& key,
        size_t block_size,
        const PolynomialConfig& poly_config);

std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_aes_128_with_polynomial(
        const std::vector<std::byte>& key,
        const PolynomialConfig& poly_config);

std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_aes_192_with_polynomial(
        const std::vector<std::byte>& key,
        const PolynomialConfig& poly_config);

std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_aes_256_with_polynomial(
        const std::vector<std::byte>& key,
        const PolynomialConfig& poly_config);

std::vector<PolynomialConfig> get_available_polynomials();
void print_available_polynomials();

class RijndaelTest : public AlgorithmTestBase {
public:
    explicit RijndaelTest(TestRunner& runner_ref) : AlgorithmTestBase(runner_ref) {}

    void run_all_rijndael_tests(const TestFileConfig& config);

    void test_with_different_polynomials(const TestFileConfig& config);

    void test_aes_128_with_polynomial(const TestFileConfig& config, const PolynomialConfig& poly_config);
    void test_aes_192_with_polynomial(const TestFileConfig& config, const PolynomialConfig& poly_config);
    void test_aes_256_with_polynomial(const TestFileConfig& config, const PolynomialConfig& poly_config);

private:
    void initialize_galois_fields();
    bool test_rijndael_file_with_polynomial(
            const std::string& file_type,
            const std::filesystem::path& file_path,
            const std::vector<std::byte>& key,
            const std::vector<std::byte>& iv,
            const PolynomialConfig& poly_config,
            const std::string& algorithm_name
    );

    void test_basic_modes_with_function(
            const std::vector<std::byte>& key,
            const std::vector<std::byte>& iv,
            std::function<std::unique_ptr<symmetric_context::SymmetricAlgorithm>(const std::vector<std::byte>&)> create_algorithm,
            const std::string& algorithm_name
    );

    void test_padding_modes_with_function(
            const std::vector<std::byte>& key,
            const std::vector<std::byte>& iv,
            std::function<std::unique_ptr<symmetric_context::SymmetricAlgorithm>(const std::vector<std::byte>&)> create_algorithm,
            const std::string& algorithm_name
    );

    void test_edge_cases_with_function(
            const std::vector<std::byte>& key,
            std::function<std::unique_ptr<symmetric_context::SymmetricAlgorithm>(const std::vector<std::byte>&)> create_algorithm,
            const std::string& algorithm_name
    );
};

void run_all_rijndael_tests_with_custom_files(
        const std::filesystem::path& text_file = "",
        const std::filesystem::path& binary_file = "",
        const std::filesystem::path& image_file = "",
        const std::filesystem::path& pdf_file = "",
        const std::filesystem::path& zip_file = "",
        const std::filesystem::path& mp4_file = ""
);

void run_rijndael_tests_with_polynomial_selection(
        const std::filesystem::path& text_file = "",
        const std::filesystem::path& binary_file = "",
        const std::filesystem::path& image_file = "",
        const std::filesystem::path& pdf_file = "",
        const std::filesystem::path& zip_file = "",
        const std::filesystem::path& mp4_file = ""
);

void run_basic_rijndael_tests();