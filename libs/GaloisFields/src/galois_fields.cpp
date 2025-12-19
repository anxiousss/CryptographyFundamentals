#include "galois_fields.hpp"

namespace galois_fields {
    std::byte GaloisField::add(const std::byte& first, const std::byte& second) {
        return first ^ second;
    }

    void GaloisField::print_element(const std::vector<std::byte>& element) {
        int index = element.size() * 8 - 1;
        for (int i = index; i > -1; --i) {
            auto bit = bits_functions::get_younger_bit(element[(index - i) / 8], i % 8);
            if (bit == 1 && i != 0)
                std::cout << "x^" << i << " + ";
            if (i == 0)
                std::cout << bit;
        }
        std::cout << std::endl;
    }

    std::pair<std::byte, std::byte> GaloisField::divide(const std::vector<std::byte> &a, const std::byte &b, bool flag) {
        uint16_t poly1 = bits_functions::bytes_to_uint16(a), poly2;
        if (flag) {
            poly2 = bits_functions::bytes_to_uint16({std::byte{0x00}, b});
        } else {
            poly2 = bits_functions::bytes_to_uint16({std::byte{0x01}, b});
        }

        auto [quotient, remainder] = bits_functions::divide_with_quotient(poly1, poly2);

        std::byte quotient_bytes = bits_functions::uint16t_to_byte(quotient);
        std::byte remainder_bytes = bits_functions::uint16t_to_byte(remainder);

        return {quotient_bytes, remainder_bytes};
    }

    std::map<size_t, std::vector<std::byte>> GaloisField::find_irreducible_polynomials() {
        for (size_t i = 0; i < 256; ++i) {
            bool is_irreducible = true;
            std::byte polynomial = static_cast<std::byte>(i);
            for (int k = 1; k < 5; ++k) {
                auto Q = polynomials[k];
                for (const auto& irr_poly: Q) {
                    if (GaloisField::divide({std::byte{0x01}, polynomial}, irr_poly, true).second == std::byte{0x00}) {
                        is_irreducible = false;
                        break;
                    }
                }
                if (!is_irreducible)
                    break;
            }

            if (is_irreducible) {
                polynomials[8].push_back(polynomial);
            }
        }

        return polynomials;
    }

    bool GaloisField::is_polynom_irreducible(const std::byte &polynomial) {

        bool is_irreducible = true;

        for (size_t k = 1; k < 5; ++k) {
            auto& Q = polynomials[k];
            for (size_t j = 0; j < Q.size(); ++j) {
                if (GaloisField::divide({std::byte{0x01}, polynomial}, Q[j], true).second == std::byte{0x00}) {
                    is_irreducible = false;
                    break;
                }
            }
            if (!is_irreducible)
                break;
        }

        return is_irreducible;
    }

    void GaloisField::print_table() {
        auto dict = find_irreducible_polynomials();

        for (const auto& [degree, polynoms]: dict) {
            std::cout << "degree -> " << degree << std::endl;
            size_t index = 1;
            for (const auto& poly: polynoms) {
                std::cout << index << ": ";
                if (degree == 8)
                    print_element({std::byte{0x01}, poly});
                else
                    print_element({poly});
                ++index;
            }
        }
    }

    std::byte GaloisField::multiply(const std::byte &a, const std::byte &b,const std::byte &mod) {

        if (!GaloisField::is_polynom_irreducible(mod))
            throw std::invalid_argument("Mod polynom is not irreducible.");

        std::vector<std::byte> mul(2);
        std::vector<size_t> indices(16, 0);
        for (int i = 7; i > -1; --i) {
            auto a_bit = bits_functions::get_younger_bit(a, i);
            for (int j = 7; j > -1; --j) {
                auto b_bit = bits_functions::get_younger_bit(b, j);
                indices[i + j] += a_bit * b_bit;;
            }
        }

        for (int i = 15; i > -1; --i) {
            bits_functions::set_younger_bit(mul[(15 - i) / 8], i % 8, indices[i] % 2);
        }

        return GaloisField::divide(mul, mod, false).second;
    }

    std::byte GaloisField::mod_exp(const std::byte &base, const std::byte& exponent, const std::byte &mod) {
        if (!GaloisField::is_polynom_irreducible(mod))
            throw std::invalid_argument("Mod polynom is not irreducible.");

        std::byte result = std::byte{0x01};
        std::byte b = base;

        uint8_t exp = std::to_integer<uint8_t>(exponent);
        while (exp > 0) {
            if (exp & 1) {
                result = multiply(result, b, mod);
            }
            b = multiply(b, b, mod);
            exp >>= 1;
        }

        return result;
    }

    std::byte GaloisField::multiplicative_inverse(const std::byte& a, const std::byte& mod) {
        if (a == std::byte{0x00})
            return std::byte{0x00};

        return GaloisField::mod_exp(a, std::byte{0xFE}, mod);
    }
}