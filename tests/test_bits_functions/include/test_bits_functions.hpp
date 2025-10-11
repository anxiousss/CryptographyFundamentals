#pragma once

#include <string>



namespace test_bits_functions {

    bool test_identity_permutation();
    bool test_reverse_permutation();
    bool test_one_based_permutation();
    bool test_youngest_bit_permutation();
    bool test_out_of_range_zero_based();
    bool test_out_of_range_one_based();
    bool test_empty_message();
    bool test_complex_permutation();
    bool test_xor_vectors();
    bool test_byte_output_operator();

    void run_all_tests();
    std::string byte_to_binary_string(std::byte b);

}