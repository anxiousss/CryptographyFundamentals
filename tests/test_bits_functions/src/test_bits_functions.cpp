#include <iostream>
#include <vector>
#include <cassert>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <bitset>
#include "bits_functions.hpp"
#include "test_bits_functions.hpp"

namespace test_bits_functions {

    std::string byte_to_binary_string(std::byte b) {
        return std::bitset<8>(std::to_integer<int>(b)).to_string();
    }

    bool test_identity_permutation() {
        std::vector<std::byte> msg = {std::byte{0b10101010}, std::byte{0b11001100}};
        std::vector<unsigned int> IP = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

        auto result = bits_functions::bits_permutation(msg, IP, bits_functions::PermutationRule::ELDEST_ZERO_BASED);

        if (result.size() != 2) {
            std::cerr << "test_identity_permutation FAILED: wrong size\n";
            return false;
        }
        if (result[0] != msg[0]) {
            std::cerr << "test_identity_permutation FAILED: first byte mismatch\n";
            return false;
        }
        if (result[1] != msg[1]) {
            std::cerr << "test_identity_permutation FAILED: second byte mismatch\n";
            return false;
        }

        std::cout << "test_identity_permutation PASSED\n";
        return true;
    }

    bool test_reverse_permutation() {
        std::vector<std::byte> msg = {std::byte{0b10101010}, std::byte{0b11001100}};
        std::vector<unsigned int> IP = {15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0};

        auto result = bits_functions::bits_permutation(msg, IP, bits_functions::PermutationRule::ELDEST_ZERO_BASED);

        if (result.size() != 2) {
            std::cerr << "test_reverse_permutation FAILED: wrong size\n";
            return false;
        }
        if (result[0] != std::byte{0b00110011}) {
            std::cerr << "test_reverse_permutation FAILED: first byte mismatch\n";
            std::cerr << "Expected: 00110011, Got: " << byte_to_binary_string(result[0]) << "\n";
            return false;
        }
        if (result[1] != std::byte{0b01010101}) {
            std::cerr << "test_reverse_permutation FAILED: second byte mismatch\n";
            std::cerr << "Expected: 01010101, Got: " << byte_to_binary_string(result[1]) << "\n";
            return false;
        }

        std::cout << "test_reverse_permutation PASSED\n";
        return true;
    }

    bool test_one_based_permutation() {
        std::vector<std::byte> msg = {std::byte{0b10101010}};
        std::vector<unsigned int> IP = {8,7,6,5,4,3,2,1};

        auto result = bits_functions::bits_permutation(msg, IP, bits_functions::PermutationRule::ELDEST_ONE_BASED);

        if (result.size() != 1) {
            std::cerr << "test_one_based_permutation FAILED: wrong size\n";
            return false;
        }
        if (result[0] != std::byte{0b01010101}) {
            std::cerr << "test_one_based_permutation FAILED: byte mismatch\n";
            std::cerr << "Expected: 01010101, Got: " << byte_to_binary_string(result[0]) << "\n";
            return false;
        }

        std::cout << "test_one_based_permutation PASSED\n";
        return true;
    }

    bool test_youngest_bit_permutation() {
        std::vector<std::byte> msg = {std::byte{0b00001111}};
        std::vector<unsigned int> IP = {4,5,6,7,0,1,2,3};

        auto result = bits_functions::bits_permutation(msg, IP, bits_functions::PermutationRule::YOUNGEST_ZERO_BASED);

        if (result.size() != 1) {
            std::cerr << "test_youngest_bit_permutation FAILED: wrong size\n";
            return false;
        }
        if (result[0] != std::byte{0b11110000}) {
            std::cerr << "test_youngest_bit_permutation FAILED: byte mismatch\n";
            std::cerr << "Expected: 11110000, Got: " << byte_to_binary_string(result[0]) << "\n";
            return false;
        }

        std::cout << "test_youngest_bit_permutation PASSED\n";
        return true;
    }

    bool test_out_of_range_zero_based() {
        std::vector<std::byte> msg = {std::byte{0xFF}};
        std::vector<unsigned int> IP = {8};

        try {
            auto result = bits_functions::bits_permutation(msg, IP, bits_functions::PermutationRule::ELDEST_ZERO_BASED);
            std::cerr << "test_out_of_range_zero_based FAILED: expected exception\n";
            return false;
        } catch (const std::out_of_range& e) {
            std::cout << "test_out_of_range_zero_based PASSED\n";
            return true;
        } catch (...) {
            std::cerr << "test_out_of_range_zero_based FAILED: wrong exception type\n";
            return false;
        }
    }

    bool test_out_of_range_one_based() {
        std::vector<std::byte> msg = {std::byte{0xFF}};
        std::vector<unsigned int> IP = {9};

        try {
            auto result = bits_functions::bits_permutation(msg, IP, bits_functions::PermutationRule::ELDEST_ONE_BASED);
            std::cerr << "test_out_of_range_one_based FAILED: expected exception\n";
            return false;
        } catch (const std::out_of_range& e) {
            std::cout << "test_out_of_range_one_based PASSED\n";
            return true;
        } catch (...) {
            std::cerr << "test_out_of_range_one_based FAILED: wrong exception type\n";
            return false;
        }
    }

    bool test_empty_message() {
        std::vector<std::byte> msg;
        std::vector<unsigned int> IP;

        auto result = bits_functions::bits_permutation(msg, IP, bits_functions::PermutationRule::ELDEST_ZERO_BASED);

        if (!result.empty()) {
            std::cerr << "test_empty_message FAILED: expected empty result\n";
            return false;
        }

        std::cout << "test_empty_message PASSED\n";
        return true;
    }

    bool test_complex_permutation() {
        std::vector<std::byte> msg = {
                std::byte{0b11001100},
                std::byte{0b10101010}
        };
        std::vector<unsigned int> IP = {
                4,5,6,7, 8,9,10,11,
                12,13,14,15, 0,1,2,3
        };

        auto result = bits_functions::bits_permutation(msg, IP, bits_functions::PermutationRule::ELDEST_ZERO_BASED);

        if (result.size() != 2) {
            std::cerr << "test_complex_permutation FAILED: wrong size\n";
            return false;
        }
        if (result[0] != std::byte{0b11001010}) {
            std::cerr << "test_complex_permutation FAILED: first byte mismatch\n";
            std::cerr << "Expected: 11001010, Got: " << byte_to_binary_string(result[0]) << "\n";
            return false;
        }
        if (result[1] != std::byte{0b10101100}) {
            std::cerr << "test_complex_permutation FAILED: second byte mismatch\n";
            std::cerr << "Expected: 10101100, Got: " << byte_to_binary_string(result[1]) << "\n";
            return false;
        }

        std::cout << "test_complex_permutation PASSED\n";
        return true;
    }

    bool test_xor_vectors() {
        std::vector<std::byte> a = {std::byte{0b10101010}, std::byte{0b11001100}};
        std::vector<std::byte> b = {std::byte{0b11110000}, std::byte{0b00110011}};

        auto result = bits_functions::xor_vectors(a, b, 2);

        if (result.size() != 2) {
            std::cerr << "test_xor_vectors FAILED: wrong size\n";
            return false;
        }
        if (result[0] != std::byte{0b01011010}) {
            std::cerr << "test_xor_vectors FAILED: first byte mismatch\n";
            std::cerr << "Expected: 01011010, Got: " << byte_to_binary_string(result[0]) << "\n";
            return false;
        }
        if (result[1] != std::byte{0b11111111}) {
            std::cerr << "test_xor_vectors FAILED: second byte mismatch\n";
            std::cerr << "Expected: 11111111, Got: " << byte_to_binary_string(result[1]) << "\n";
            return false;
        }

        std::cout << "test_xor_vectors PASSED\n";
        return true;
    }

    bool test_byte_output_operator() {
        std::byte b = std::byte{0b11001010};
        std::ostringstream oss;
        oss << b;

        std::string result = oss.str();
        if (result != "11001010") {
            std::cerr << "test_byte_output_operator FAILED: output mismatch\n";
            std::cerr << "Expected: 11001010, Got: " << result << "\n";
            return false;
        }

        std::cout << "test_byte_output_operator PASSED\n";
        return true;
    }

    void run_all_tests() {
        int passed = 0;
        int total = 0;

        auto run_test = [&](bool (*test_func)(), const std::string& test_name) {
            total++;
            std::cout << "Running " << test_name << "... ";
            if (test_func()) {
                passed++;
                std::cout << "PASSED\n";
            } else {
                std::cerr << test_name << " FAILED!\n";
            }
        };

        std::cout << "=== Running Bits Functions Tests ===\n";

        run_test(test_identity_permutation, "test_identity_permutation");
        run_test(test_reverse_permutation, "test_reverse_permutation");
        run_test(test_one_based_permutation, "test_one_based_permutation");
        run_test(test_youngest_bit_permutation, "test_youngest_bit_permutation");
        run_test(test_out_of_range_zero_based, "test_out_of_range_zero_based");
        run_test(test_out_of_range_one_based, "test_out_of_range_one_based");
        run_test(test_empty_message, "test_empty_message");
        run_test(test_complex_permutation, "test_complex_permutation");
        run_test(test_xor_vectors, "test_xor_vectors");
        run_test(test_byte_output_operator, "test_byte_output_operator");

        std::cout << "=== Test Results: " << passed << "/" << total << " passed ===\n";

        if (passed == total) {
            std::cout << "ALL TESTS PASSED! \n";
        } else {
            std::cout << "SOME TESTS FAILED! \n";
        }
    }

} // namespace test_bits_functions