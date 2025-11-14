#pragma once

#include <tuple>
#include <utility>
#include <iostream>
#include <boost/multiprecision/cpp_int.hpp>

namespace number_functions {
    class NumberTheoryFunctions {
    public:
        static boost::multiprecision::cpp_int jacobi_symbol(const boost::multiprecision::cpp_int &a,
                                                            const boost::multiprecision::cpp_int &b);

        static boost::multiprecision::cpp_int legendre_symbol(const boost::multiprecision::cpp_int &a,
                                                              const boost::multiprecision::cpp_int &b);

        static boost::multiprecision::cpp_int gcd(const boost::multiprecision::cpp_int &a,
                                                  const boost::multiprecision::cpp_int &b);

        static std::tuple<boost::multiprecision::cpp_int, boost::multiprecision::cpp_int, boost::multiprecision::cpp_int>
        extended_gcd(const boost::multiprecision::cpp_int &a,const boost::multiprecision::cpp_int &b);

        static boost::multiprecision::cpp_int mod_exp(const boost::multiprecision::cpp_int &base,
                                                      const boost::multiprecision::cpp_int &exp,
                                                      const boost::multiprecision::cpp_int &mod);
    };
}
