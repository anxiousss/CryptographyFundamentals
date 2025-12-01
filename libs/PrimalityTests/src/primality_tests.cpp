#include "primality_tests.hpp"

namespace primality_tests {

    double PrimalityTest::is_prime(const boost::multiprecision::cpp_int &p, double min_probability) {
        if (p < 2) return 0.0;
        if (p == 2 || p == 3) return 1.0;
        if (p % 2 == 0) return 0.0;

        if (min_probability < 0.5 || min_probability > 1)
            throw std::invalid_argument("Invalid probability value.");

        size_t k = n_iterations(min_probability);
        for (size_t i = 0; i < k; ++i) {
            if (iteration(p) == NumberState::COMPOSITE) return 0;
        }
        primality_witnesses.clear();
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
            if (primality_witnesses.size() == p - 2) return NumberState::MAYBEPRIME;
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

        if (number_functions::NumberTheoryFunctions::gcd(a, p) != 1) {
            return NumberState::COMPOSITE;
        }

        boost::multiprecision::cpp_int jacobi = number_functions::NumberTheoryFunctions::jacobi_symbol(a, p);

        boost::multiprecision::cpp_int exponent = (p - 1) / 2;
        boost::multiprecision::cpp_int mod_val = number_functions::NumberTheoryFunctions::mod_exp(a, exponent, p);


        if (jacobi == 1 && mod_val != 1) {
            return NumberState::COMPOSITE;
        }
        if (jacobi == -1 && mod_val != p - 1) {
            return NumberState::COMPOSITE;
        }
        if (jacobi == 0) {
            return NumberState::COMPOSITE;
        }

        return NumberState::MAYBEPRIME;
    }

    NumberState MillerRabinPrimalityTest::iteration(const boost::multiprecision::cpp_int &p) {
        boost::multiprecision::cpp_int n = p - 1;
        boost::multiprecision::cpp_int s = 0;
        boost::multiprecision::cpp_int t = n;

        while (t % 2 == 0) {
            s++;
            t /= 2;
        }

        boost::random::uniform_int_distribution<boost::multiprecision::cpp_int> dist(2, p - 2);
        boost::multiprecision::cpp_int a;

        do {
            a = dist(gen);
        } while (primality_witnesses.count(a) > 0);

        auto x = number_functions::NumberTheoryFunctions::mod_exp(a, t, p);

        if (x == 1 || x == p - 1) {
            return NumberState::MAYBEPRIME;
        }

        for (boost::multiprecision::cpp_int i = 0; i < s - 1; ++i) {
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
        return 1.0 - std::pow(0.25, static_cast<double>(k));
    }

    size_t MillerRabinPrimalityTest::n_iterations(double probability) {
        if (probability >= 1.0) return 0;
        return static_cast<size_t>(std::ceil(-std::log(1.0 - probability) / std::log(4.0)));
    }
}