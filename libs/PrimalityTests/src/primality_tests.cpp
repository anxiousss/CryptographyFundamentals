#include "primality_tests.hpp"

namespace primality_tests {

    NumberState FermatPrimalityTest::iteration(const boost::multiprecision::cpp_int &p) {
        boost::random::uniform_int_distribution<boost::multiprecision::cpp_int> dist(2, p - 1);
        boost::multiprecision::cpp_int a = dist(gen);
        if (std::find(primality_witnesses.begin(), primality_witnesses.end(), a) != primality_witnesses.end())
            a = dist(gen);
        primality_witnesses.push_back(a);

        if (number_functions::NumberTheoryFunctions::gcd(a, p) != 1 ||
                number_functions::NumberTheoryFunctions::mod_exp(a, p - 1, p) != p)
            return NumberState::COMPOSITE;

        return NumberState::MAYBEPRIME;
    }

    NumberState SolovayStrassenPrimalityTest::iteration(const boost::multiprecision::cpp_int &p) {
        boost::random::uniform_int_distribution<boost::multiprecision::cpp_int> dist(2, p - 1);
        boost::multiprecision::cpp_int a = dist(gen);
        if (std::find(primality_witnesses.begin(), primality_witnesses.end(), a) != primality_witnesses.end())
            a = dist(gen);
        primality_witnesses.push_back(a);

        if (number_functions::NumberTheoryFunctions::gcd(a, p) != 1 ||
                number_functions::NumberTheoryFunctions::mod_exp(a, (p - 1) / 2, p) !=
                number_functions::NumberTheoryFunctions::jacobi_symbol(a, p))
            return NumberState::COMPOSITE;

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
        boost::random::uniform_int_distribution<boost::multiprecision::cpp_int> dist(2, p - 1);
        boost::multiprecision::cpp_int a = dist(gen);
        if (std::find(primality_witnesses.begin(), primality_witnesses.end(), a) != primality_witnesses.end())
            a = dist(gen);
        primality_witnesses.push_back(a);
        auto x = number_functions::NumberTheoryFunctions::mod_exp(a, t, p);
        if (x != 1 || x != p - 1) {
            for (int j = 1; j < s  -1; ++j) {
                x = number_functions::NumberTheoryFunctions::mod_exp(x, 2, p);
                if (x == 1)
                    return NumberState::COMPOSITE;

                if (x == p - 1)
                    return NumberState::MAYBEPRIME;
            }
        }
        return NumberState::COMPOSITE;
    }
}