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

    std::vector<std::byte> GaloisField::divide(const std::vector<std::byte> &a, const std::vector<std::byte> &b) {
        uint16_t poly1 = bits_functions::bytes_to_uint16_be(a), poly2 = bits_functions::bytes_to_uint16_be(b);
        if (poly2 == 0) {
            throw std::invalid_argument("Division by zero polynomial");
        }

        int deg1 = bits_functions::polynomial_degree(poly1);
        int deg2 = bits_functions::polynomial_degree(poly2);

        while (deg1 >= deg2 && poly1 != 0) {
            int shift = deg1 - deg2;

            poly1 ^= (poly2 << shift);

            deg1 = bits_functions::polynomial_degree(poly1);
        }

        std::vector<std::byte> result = bits_functions::uint16_to_bytes_be(poly1);
        return result;
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
                        if (GaloisField::divide(polynominal, Q[j]) == std::vector{std::byte{0x00}, std::byte{0x00}} ) {
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



        return GaloisField::divide(mul, mod);
    }

    std::vector<std::byte>
    GaloisField::multiplicative_inverse(const std::vector<std::byte> &a, const std::vector<std::byte> &mod) {
        if (a == std::vector{std::byte{0x00}, std::byte{0x00}})
            return std::vector{std::byte{0x00}, std::byte{0x00}};

        auto [r, s, q] = number_functions::NumberTheoryFunctions::extended_gcd(
                number_functions::NumberTheoryFunctions::bytes_to_cpp_int(a),
                number_functions::NumberTheoryFunctions::bytes_to_cpp_int(mod));

        return
    }
}