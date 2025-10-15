#pragma once

#include <iostream>
#include <vector>
#include <cassert>
#include <string>
#include <memory>
#include "symmetric_algorithm.hpp"

using namespace symmerical_algorithm;

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

// Helper functions for testing
bool compare_byte_vectors(const std::vector<std::byte>& v1, const std::vector<std::byte>& v2);
void print_byte_vector(const std::vector<std::byte>& data);

// Test function declarations
void test_ecb_encryption_decryption(TestRunner& runner);
void test_cbc_encryption_decryption(TestRunner& runner);
void test_pcbc_encryption_decryption(TestRunner& runner);
void test_cfb_encryption_decryption(TestRunner& runner);
void test_ofb_encryption_decryption(TestRunner& runner);
void test_ctr_encryption_decryption(TestRunner& runner);
void test_random_delta_encryption_decryption(TestRunner& runner);
void test_different_padding_modes(TestRunner& runner);
void test_empty_data(TestRunner& runner);
void test_large_data(TestRunner& runner);
void test_thread_safety(TestRunner& runner);

// Debug function to check block size issues
void test_block_size_issues(TestRunner& runner);

// Main test runner function
int run_all_tests();