#pragma once

#include "boost/random.hpp"
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
    public:
        double is_prime(const boost::multiprecision::cpp_int& p, double min_probability) final;
    protected:
        virtual NumberState iteration(const boost::multiprecision::cpp_int& p);
    };

    class FermatPrimalityTest: public PrimalityTest {
    private:
        std::vector<boost::multiprecision::cpp_int> primality_witnesses;
        boost::random::mt19937 gen;

    public:
        NumberState iteration(const boost::multiprecision::cpp_int& p) override;
    };

    class SolovayStrassenPrimalityTest: PrimalityTest {
    private:
        std::vector<boost::multiprecision::cpp_int> primality_witnesses;
        boost::random::mt19937 gen;

    public:
        NumberState iteration(const boost::multiprecision::cpp_int& p) override;
    };

    class MillerRabinPrimalityTest: public PrimalityTest {
    private:
        std::vector<boost::multiprecision::cpp_int> primality_witnesses;
        boost::random::mt19937 gen;
        boost::multiprecision::cpp_int t, s;

    public:
        void decomposition_determination(const boost::multiprecision::cpp_int &p);
        NumberState iteration(const boost::multiprecision::cpp_int& p) override;
    };

}