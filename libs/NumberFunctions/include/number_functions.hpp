#pragma once

#include <tuple>
#include <utility>
#include <iostream>
#include <boost/multiprecision/cpp_int.hpp>

namespace number_functions {
    class NumberTheoryFunctions {
    public:

        static std::vector<std::byte> cpp_int_to_bytes(const boost::multiprecision::cpp_int& num);

        static boost::multiprecision::cpp_int bytes_to_cpp_int(const std::vector<std::byte>& data);

        static boost::multiprecision::cpp_int Jacobi_symbol(const boost::multiprecision::cpp_int &a,
                                                            const boost::multiprecision::cpp_int &b);

        static boost::multiprecision::cpp_int Legendre_symbol(const boost::multiprecision::cpp_int &a,
                                                              const boost::multiprecision::cpp_int &b);

        static boost::multiprecision::cpp_int gcd(const boost::multiprecision::cpp_int &a,
                                                  const boost::multiprecision::cpp_int &b);

        static std::tuple<boost::multiprecision::cpp_int, boost::multiprecision::cpp_int, boost::multiprecision::cpp_int>
        extended_gcd(const boost::multiprecision::cpp_int &a,const boost::multiprecision::cpp_int &b);

        static boost::multiprecision::cpp_int mod_exp(const boost::multiprecision::cpp_int &base,
                                                      const boost::multiprecision::cpp_int &exp,
                                                      const boost::multiprecision::cpp_int &mod);

        static std::vector<boost::multiprecision::cpp_int>
        make_continued_fraction(const boost::multiprecision::cpp_int &a, const boost::multiprecision::cpp_int& b);
    };
}
