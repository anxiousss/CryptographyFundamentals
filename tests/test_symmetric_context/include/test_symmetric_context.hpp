#pragma once

#include <iostream>
#include <vector>
#include <cassert>
#include <string>
#include <memory>
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

void print_byte_vector(const std::vector<std::byte>& data);
// Создание DES алгоритма с правильными параметрами
std::unique_ptr<des::DES> create_des_algorithm(const std::vector<std::byte>& key);

void test_basic_des(TestRunner& runner);
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
void test_image_and_text_files(TestRunner& runner);
int run_all_tests();