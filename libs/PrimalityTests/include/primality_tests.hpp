#pragma once

#include "boost/random/random_device.hpp"
#include "boost/random.hpp"
#include <unordered_set>
#include "number_functions.hpp"

namespace primality_tests {
    enum class NumberState {
        COMPOSITE,
        MAYBEPRIME
    };

    class ProbabilisticPrimalityTest {
    public:
        virtual double is_prime(const boost::multiprecision::cpp_int& p, double min_probability) = 0;
    };

    class PrimalityTest: public ProbabilisticPrimalityTest {
    private:
        boost::random::random_device gen;
        std::unordered_set<boost::multiprecision::cpp_int> primality_witnesses;
    public:
        double is_prime(const boost::multiprecision::cpp_int& p, double min_probability) final;
    protected:
        virtual NumberState iteration(const boost::multiprecision::cpp_int& a, const boost::multiprecision::cpp_int& p) = 0;
        virtual size_t n_iterations(double probability);
        virtual double prime_probability(size_t k);
    };

    class FermatPrimalityTest: public PrimalityTest {
    public:
        NumberState iteration(const boost::multiprecision::cpp_int& a, const boost::multiprecision::cpp_int& p) override;
    };

    class SolovayStrassenPrimalityTest: public PrimalityTest {
    private:
    public:
        NumberState iteration(const boost::multiprecision::cpp_int& a, const boost::multiprecision::cpp_int& p) override;
    };

    class MillerRabinPrimalityTest: public PrimalityTest {
    public:
        NumberState iteration(const boost::multiprecision::cpp_int& a, const boost::multiprecision::cpp_int& p) override;
        double prime_probability(size_t k) override;
        size_t n_iterations(double probability) override;
    };

}