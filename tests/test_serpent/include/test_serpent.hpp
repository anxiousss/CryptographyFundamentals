#pragma once

#include "test_utility.hpp"
#include "serpent.hpp"
#include <memory>

// Функция для создания экземпляра Serpent
std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_serpent_algorithm(const std::vector<std::byte>& key);

// Класс для тестирования Serpent
class SerpentTest : public AlgorithmTestBase {
public:
    explicit SerpentTest(TestRunner& runner_ref);

    void run_all_tests();

private:
    void test_key_sizes();
    void test_known_vectors();
    void test_encryption_decryption_consistency();
    void test_different_key_lengths();
    void test_performance();
};

// Функция для тестирования файловых операций
void test_serpent_file_operations(TestRunner& runner, const TestFileConfig& config);