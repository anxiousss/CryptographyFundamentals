#pragma once

#include <vector>
#include <cstddef>
#include <cstring>
#include <bit>
#include <map>
#include "bits_functions.hpp"
#include "number_functions.hpp"

namespace galois_fields {
    inline std::map<size_t, std::vector<std::byte>> polynomials = {{1, {std::byte{0x02}, std::byte{0x03}}},
                                                            {2, {std::byte{0x07}}},
                                                            {3, {std::byte{0x0B}, std::byte{0x0D}}},
                                                            {4, {std::byte{0x13}, std::byte{0x19}, std::byte{0x1F}}},
                                                            {8, {}}};

    class GaloisField {
    public:
        static std::byte mod_exp(const std::byte& base, const std::byte& exp, const std::byte& mod);

        static std::byte add(const std::byte& first, const std::byte& second);

        static std::byte multiply(const std::byte& a, const std::byte& b, const std::byte& mod);

        static std::byte multiplicative_inverse(const std::byte& a, const std::byte& mod);

        static bool is_polynom_irreducible(const std::byte& polynomial);

        static void print_table();

        static void print_element(const std::vector<std::byte>& el);

        static std::pair<std::byte, std::byte> divide(const std::vector<std::byte>& a,
                                                      const std::byte& b, bool is_check);

        static std::map<size_t, std::vector<std::byte>> find_irreducible_polynomials();
    };
}