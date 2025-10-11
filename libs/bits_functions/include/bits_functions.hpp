#pragma once

#include <bitset>
#include <iostream>
#include <cstddef>
#include <vector>

namespace bits_functions {
    enum class PermutationRule {
        ELDEST_ZERO_BASED,
        ELDEST_ONE_BASED,
        YOUNGEST_ZERO_BASED,
        YOUNGEST_ONE_BASED
    };



    void set_eldest_bit(std::byte &b, size_t n, bool value);

    bool get_eldest_bit(std::byte b, size_t n);

    bool get_younger_bit(std::byte b, size_t n);

    void set_younger_bit(std::byte &b, size_t n, bool value);

    std::vector<std::byte> xor_vectors(const std::vector<std::byte> &a, const std::vector<std::byte> &b, size_t size);

    std::vector<std::byte> bits_permutation(const std::vector<std::byte> &msg, const std::vector<unsigned int> &IP,
                                            PermutationRule rule);

}

std::ostream &operator<<(std::ostream &os, std::byte b);
