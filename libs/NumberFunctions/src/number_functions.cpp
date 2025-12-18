#include "number_functions.hpp"

namespace number_functions {

    constexpr unsigned char reverse_bits(unsigned char b) {
        b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
        b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
        b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
        return b;
    }

    boost::multiprecision::cpp_int  NumberTheoryFunctions::bytes_to_cpp_int(const std::vector<std::byte>& data) {
        boost::multiprecision::cpp_int result = 0;
        boost::multiprecision::cpp_int base = 1;

        for (std::byte b : data) {
            unsigned char byte_val = static_cast<unsigned char>(b);
            unsigned char reversed_byte = reverse_bits(byte_val);
            result += static_cast<boost::multiprecision::cpp_int>(reversed_byte) * base;
            base <<= 8;
        }
        return result;
    }

    std::vector<std::byte> NumberTheoryFunctions::cpp_int_to_bytes(const boost::multiprecision::cpp_int& num) {
        if (num < 0) {
            throw std::invalid_argument("Negative numbers are not supported");
        }
        if (num == 0) {
            return {std::byte{0}};
        }

        std::vector<unsigned char> raw_bytes;
        boost::multiprecision::export_bits(num, std::back_inserter(raw_bytes), 8, false);

        std::vector<std::byte> result;
        result.reserve(raw_bytes.size());
        for (unsigned char b : raw_bytes) {
            result.push_back(static_cast<std::byte>(reverse_bits(b)));
        }
        return result;
    }

    boost::multiprecision::cpp_int NumberTheoryFunctions::gcd(const boost::multiprecision::cpp_int &a,
                                                              const boost::multiprecision::cpp_int &b) {
        boost::multiprecision::cpp_int x = a, y = b;
        while (y != 0) {
            boost::multiprecision::cpp_int r = x % y;
            x = y;
            y = r;
        }
        return x;
    }

    std::tuple<boost::multiprecision::cpp_int, boost::multiprecision::cpp_int, boost::multiprecision::cpp_int>
            NumberTheoryFunctions::extended_gcd(const boost::multiprecision::cpp_int &a,
                                                const boost::multiprecision::cpp_int &b) {
        boost::multiprecision::cpp_int r0 = a, r1 = b;
        boost::multiprecision::cpp_int x0 = 1, x1 = 0;
        boost::multiprecision::cpp_int y0 = 0, y1 = 1;

        if (r0 < 0) {
            r0 = -r0;
            x0 = -x0;
            y0 = -y0;
        }

        while (true) {
            boost::multiprecision::cpp_int q = r0 / r1, r2 = r0 % r1, x2 = x0 - q * x1, y2 = y0 - q * y1;
            r0 = r1; r1 = r2; x0 = x1; x1 = x2; y0 = y1; y1 = y2;
            if (r1 == 0) {
                return std::make_tuple(r0, x0, y0);
            }
        }
     }

    boost::multiprecision::cpp_int NumberTheoryFunctions::mod_exp(const boost::multiprecision::cpp_int &base,
                                                                  const boost::multiprecision::cpp_int &exp,
                                                                  const boost::multiprecision::cpp_int &mod) {
        if (mod == 1) return 0;
        boost::multiprecision::cpp_int result = 1;
        boost::multiprecision::cpp_int b = base % mod;
        boost::multiprecision::cpp_int e = exp;
        while (e > 0) {
            if (e & 1) {
                result = (result * b) % mod;
            }
            b = (b * b) % mod;
            e >>= 1;
        }
        return result;
    }

    boost::multiprecision::cpp_int NumberTheoryFunctions::Legendre_symbol(const boost::multiprecision::cpp_int &a,
                                                   const boost::multiprecision::cpp_int &p) {
        if (p <= 0 || p % 2 == 0) {
            throw std::invalid_argument("Legendre symbol is defined only for positive odd n");

        }
        if (a % p == 0) return 0;
        auto exponent = (p - 1) / 2;
        auto value = NumberTheoryFunctions::mod_exp(a, exponent, p);
        return (value == 1) ? 1 : -1;
    }

    boost::multiprecision::cpp_int NumberTheoryFunctions::Jacobi_symbol(const boost::multiprecision::cpp_int &a,
                                                                        const boost::multiprecision::cpp_int &n) {
        if (n <= 0 || n % 2 == 0) {
            throw std::invalid_argument("Jacobi symbol is defined only for positive odd n");
        }

        boost::multiprecision::cpp_int x = a % n;
        boost::multiprecision::cpp_int y = n;
        int j = 1;

        while (x != 0) {
            while (x % 2 == 0) {
                x /= 2;
                boost::multiprecision::cpp_int r = y % 8;
                if (r == 3 || r == 5) {
                    j = -j;
                }
            }

            std::swap(x, y);

            if (x % 4 == 3 && y % 4 == 3) {
                j = -j;
            }

            x %= y;
        }

        return (y == 1) ? j : 0;
    }

    std::vector<boost::multiprecision::cpp_int>
    NumberTheoryFunctions::make_continued_fraction(const boost::multiprecision::cpp_int &x,
                                                   const boost::multiprecision::cpp_int& y) {
        boost::multiprecision::cpp_int a = x, b = y, numerator = x;
        std::vector<boost::multiprecision::cpp_int> fraction_elements = {a / b};

        boost::multiprecision::swap(a, b);
        while (numerator != 0) {
            auto whole_part = a / b;
            numerator = a - b * whole_part;
            fraction_elements.push_back(whole_part);
            a = b;
            b = numerator;
        }
        return fraction_elements;
    }
}

