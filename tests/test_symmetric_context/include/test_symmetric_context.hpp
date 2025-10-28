#pragma once

#include <iostream>
#include <vector>
#include <cassert>
#include <string>
#include <memory>
#include <fstream>
#include <filesystem>
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

std::unique_ptr<des::DES> create_des_algorithm(const std::vector<std::byte>& key);
std::unique_ptr<deal::DEAL> create_deal_algorithm_128(const std::vector<std::byte>& key);
std::unique_ptr<deal::DEAL> create_deal_algorithm_192(const std::vector<std::byte>& key);
std::unique_ptr<deal::DEAL> create_deal_algorithm_256(const std::vector<std::byte>& key);

void test_basic_des(TestRunner& runner);
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
void test_image_and_text_files_des(TestRunner& runner);

void test_basic_deal_128(TestRunner& runner);
void test_basic_deal_192(TestRunner& runner);
void test_basic_deal_256(TestRunner& runner);
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
void test_image_and_text_files_deal(TestRunner& runner);

int run_all_des_tests();
int run_all_deal_tests();
int run_all_tests();