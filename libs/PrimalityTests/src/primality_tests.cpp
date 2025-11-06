#include "primality_tests.hpp"

namespace primality_tests {

    double PrimalityTest::is_prime(const boost::multiprecision::cpp_int &p, double min_probability) {
        if (p < 2) return 0.0;
        if (p == 2) return 1.0;
        if (p % 2 == 0) return 0.0;

        if (min_probability < 0.5 || min_probability > 1)
            throw std::invalid_argument("Invalid probability value.");

        size_t k = n_iterations(min_probability);
        for (size_t i = 0; i < k    ; ++i) {
            if (iteration(p) == NumberState::COMPOSITE) return 0;
        }
        return prime_probability(k);
    }

    size_t PrimalityTest::n_iterations(double probability) {
        return static_cast<size_t>(std::ceil(std::log(1.0 / (1.0 - probability)) / std::log(2.0)));
    }

    double PrimalityTest::prime_probability(size_t k) {
        return 1.0 - 1.0 / std::pow(2.0, static_cast<double>(k));
    }

    NumberState FermatPrimalityTest::iteration(const boost::multiprecision::cpp_int &p) {
        boost::random::uniform_int_distribution<boost::multiprecision::cpp_int> dist(2, p - 1);

        boost::multiprecision::cpp_int a;
        do {
            a = dist(gen);
        } while (primality_witnesses.count(a) > 0);

        primality_witnesses.insert(a);

        if (number_functions::NumberTheoryFunctions::gcd(a, p) != 1 ||
            number_functions::NumberTheoryFunctions::mod_exp(a, p - 1, p) != 1) {
            return NumberState::COMPOSITE;
        }

        return NumberState::MAYBEPRIME;
    }

    NumberState SolovayStrassenPrimalityTest::iteration(const boost::multiprecision::cpp_int &p) {
        boost::random::uniform_int_distribution<boost::multiprecision::cpp_int> dist(2, p - 1);

        boost::multiprecision::cpp_int a;
        do {
            a = dist(gen);
        } while (primality_witnesses.count(a) > 0);

        primality_witnesses.insert(a);

        const auto jacobi = number_functions::NumberTheoryFunctions::jacobi_symbol(a, p);
        if (jacobi == 0 || number_functions::NumberTheoryFunctions::gcd(a, p) != 1) {
            return NumberState::COMPOSITE;
        }

        boost::multiprecision::cpp_int normalized_jacobi = jacobi;
        if (jacobi == -1) {
            normalized_jacobi = p - 1;
        }

        const auto mod_val = number_functions::NumberTheoryFunctions::mod_exp(a, (p - 1) / 2, p);

        if (mod_val != normalized_jacobi) {
            return NumberState::COMPOSITE;
        }

        return NumberState::MAYBEPRIME;
    }

    void MillerRabinPrimalityTest::decomposition_determination(const boost::multiprecision::cpp_int &p) {
        auto n = p;
        while (n % 2 == 0) {
            ++s;
            n /= 2;
        }
        t = n;
    }


    NumberState MillerRabinPrimalityTest::iteration(const boost::multiprecision::cpp_int &p) {
        decomposition_determination(p);

        boost::random::uniform_int_distribution<boost::multiprecision::cpp_int> dist(2, p - 1);

        boost::multiprecision::cpp_int a;
        do {
            a = dist(gen);
        } while (primality_witnesses.count(a) > 0);

        primality_witnesses.insert(a);

        auto x = number_functions::NumberTheoryFunctions::mod_exp(a, t, p);

        if (x == 1 || x == p - 1) {
            return NumberState::MAYBEPRIME;
        }

        for (boost::multiprecision::cpp_int j = 1; j < s; ++j) {
            x = number_functions::NumberTheoryFunctions::mod_exp(x, 2, p);
            if (x == 1) {
                return NumberState::COMPOSITE;
            }
            if (x == p - 1) {
                return NumberState::MAYBEPRIME;
            }
        }

        return NumberState::COMPOSITE;
    }

    double MillerRabinPrimalityTest::prime_probability(size_t k) {
        return 1.0 - 1.0 / std::pow(4.0, static_cast<double>(k));
    }

    size_t MillerRabinPrimalityTest::n_iterations(double probability) {
        return static_cast<size_t>(std::ceil(std::log(1.0 / (1.0 - probability)) / (2.0 * std::log(2.0))));
    }
}