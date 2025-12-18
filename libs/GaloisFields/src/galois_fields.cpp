#include "galois_fields.hpp"

namespace galois_fields {
    std::vector<std::byte> GaloisField::add(const std::vector<std::byte>& a, const std::vector<std::byte>& b) {
        auto sum = bits_functions::xor_vectors(a, b, a.size());
        return sum;
    }

    void GaloisField::print_element(const std::vector<std::byte>& element) {
        for (int i = element.size() * 8 - 1; i > -1; --i) {
            auto bit = bits_functions::get_eldest_bit(element[i / 8], i % 8);
            if (bit == 1 && i != 0)
                std::cout << "x^" << i << " + ";
            if (i == 0)
                std::cout << bit;
        }
        std::cout << std::endl;
    }

    std::pair<std::vector<std::byte>, std::vector<std::byte>> GaloisField::divide(const std::vector<std::byte> &a, const std::vector<std::byte> &b) {
        uint16_t poly1 = bits_functions::bytes_to_uint16_be(a);
        uint16_t poly2 = bits_functions::bytes_to_uint16_be(b);

        auto [quotient, remainder] = bits_functions::divide_with_quotient(poly1, poly2);

        std::vector<std::byte> quotient_bytes = bits_functions::uint16_to_bytes_be(quotient);
        std::vector<std::byte> remainder_bytes = bits_functions::uint16_to_bytes_be(remainder);

        return {quotient_bytes, remainder_bytes};
    }

    std::map<size_t, std::vector<std::vector<std::byte>>> GaloisField::find_irreducible_polynomials() {
        std::map<size_t, std::vector<std::vector<std::byte>>> polynominals = {{1, {{std::byte{0b01000000}, std::byte{0x00}},
                                                                                        {std::byte{0b11000000}, std::byte{0x00}}}}};



        for (uint16_t d = 2; d <= 8; ++d) {
            uint16_t start = 1 << d;
            uint16_t end = (1 << (d + 1));

            for (uint16_t i = start; i < end; ++i) {
                if ((i & 1) == 0 || std::popcount(i) % 2 == 0) continue;

                bool is_irreducible = true;
                std::vector<std::byte> polynominal = bits_functions::uint16_to_bytes_be(i);

                for (size_t k = 1; k <= d / 2; ++k) {
                    auto& Q = polynominals[k];
                    for (size_t j = 0; j < Q.size(); ++j) {
                        if (GaloisField::divide(polynominal, Q[j]).second == std::vector{std::byte{0x00}, std::byte{0x00}} ) {
                            is_irreducible = false;
                            break;
                        }
                    }
                    if (!is_irreducible)
                        break;
                }

                if (is_irreducible) {
                    if (!polynominals.contains(d))
                        polynominals[d] = {};
                    polynominals[d].push_back(polynominal);
                }
            }
        }

        return polynominals;
    }

    void GaloisField::print_table() {
        auto dict = find_irreducible_polynomials();

        for (const auto& [degree, polynominals]: dict) {
            std::cout << "degree -> " << degree << std::endl;
            for (const auto& poly: polynominals) {
                print_element(poly);
            }
        }
    }

    std::vector<std::byte>  GaloisField::multiply(const std::vector<std::byte> &a, const std::vector<std::byte> &b,
                                      const std::vector<std::byte> &mod) {

        if (!GaloisField::is_polynom_irreducible(mod))
            throw std::invalid_argument("Mod polynom is not irreducible.");

        std::vector<std::byte> mul(2);
        std::vector<size_t> indices(16, 0);
        for (size_t i = 0; i < 8; ++i) {
            auto a_bit = bits_functions::get_eldest_bit(a[0], i);
            for (size_t j = 0; j < 8; ++j) {
                auto b_bit = bits_functions::get_eldest_bit(b[0], j);
                indices[i + j] += a_bit * b_bit;;
            }
        }

        for (int i = 0; i < 16; ++i) {
            bits_functions::set_eldest_bit(mul[i / 8], i % 8, indices[i] % 2);
        }

        return GaloisField::divide(mul, mod).second;
    }

    std::vector<std::byte>
    GaloisField::mod_exp(const std::vector<std::byte> &base, int exp, const std::vector<std::byte> &mod) {
        if (!GaloisField::is_polynom_irreducible(mod))
            throw std::invalid_argument("Mod polynom is not irreducible.");

        std::vector<std::byte> result = {std::byte{0b10000000}, std::byte{0x00}};
        std::vector<std::byte> b = base;

        while (exp > 0) {
            if (exp & 1) {
                result = multiply(result, b, mod);
            }
            b = multiply(b, b, mod);
            exp >>= 1;
        }

        return result;
    }

    std::vector<std::byte>
    GaloisField::multiplicative_inverse(const std::vector<std::byte> &a, const std::vector<std::byte> &mod) {
        if (a == std::vector{std::byte{0x00}, std::byte{0x00}})
            return std::vector{std::byte{0x00}, std::byte{0x00}};

        return GaloisField::mod_exp(a, 254, mod);
    }

    bool GaloisField::is_polynom_irreducible(const std::vector<std::byte> &polynominal) {
        std::map<size_t, std::vector<std::vector<std::byte>>> table= {{1, {{std::byte{0b01000000}, std::byte{0x00}},
                                                                                {std::byte{0b11000000}, std::byte{0x00}}}},
                                                                      {2, {{std::byte{0b11100000}, std::byte{0x00}}}},
                                                                      {3, {{std::byte{0b11010000}, std::byte{0x00}},
                                                                                 {std::byte{0b10110000}, std::byte{0x00}}}},
                                                                      {4, {{std::byte{0b11001000}, std::byte{0x00}},
                                                                                 {std::byte{0b10011000}, std::byte{0x00}},
                                                                                 {std::byte{0b11111000}, std::byte{0x00}}}}};

        bool is_irreducible = true;

        for (size_t k = 1; k <= 4; ++k) {
            auto& Q = table[k];
            for (size_t j = 0; j < Q.size(); ++j) {
                if (Q[j] == polynominal) return true;
                if (GaloisField::divide(polynominal, Q[j]).second == std::vector{std::byte{0x00}, std::byte{0x00}} ) {
                    is_irreducible = false;
                    break;
                }
            }
            if (!is_irreducible)
                break;
        }

        return is_irreducible;
    }
}