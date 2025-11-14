#include "rsa.hpp"

namespace rsa {

    RsaKeysGeneration::RsaKeysGeneration(TestTypes type_, double probability_, size_t bit_length_):
            min_probability(probability_), bit_length(bit_length_) {
        switch (type_) {
            case TestTypes::FermaTest:
                this->primality_test = std::make_shared<primality_tests::FermatPrimalityTest>();
            case TestTypes::SolovayStrassenTest:
                this->primality_test = std::make_shared<primality_tests::SolovayStrassenPrimalityTest>();
            case TestTypes::MilerRabinTest:
                this->primality_test = std::make_shared<primality_tests::MillerRabinPrimalityTest>();
        }
    }

    std::pair<std::pair<boost::multiprecision::cpp_int, boost::multiprecision::cpp_int>,
            std::pair<boost::multiprecision::cpp_int, boost::multiprecision::cpp_int>>
    RsaKeysGeneration::generate_keys() {
        boost::random::uniform_int_distribution<boost::multiprecision::cpp_int>
                dist(0, (boost::multiprecision::cpp_int{1} << bit_length));

        boost::random::random_device rd;
        boost::multiprecision::cpp_int p, q;
        bool found = false;
        while (true) {
            p = dist(rd);
            if (this->primality_test->is_prime(p, min_probability) >= min_probability) {
                while (true) {
                    q = dist(rd);
                    if (this->primality_test->is_prime(q, min_probability) >= min_probability) {
                        found = true;
                        break;
                    }
                }
            }
            if (found)
                break;
        }

        boost::multiprecision::cpp_int n = p * q;
        boost::multiprecision::cpp_int e = 65537;
        boost::multiprecision::cpp_int phi_n = (p - 1) * (q - 1);

        auto [_, d, __] = number_functions::NumberTheoryFunctions::extended_gcd(e, phi_n);
        d = d % phi_n;
        if (d < 0) {
            d += phi_n;
        }

        // Проверка на атаку винера.

        return std::make_pair(std::make_pair(e, n), std::make_pair(d, n));
    }
}