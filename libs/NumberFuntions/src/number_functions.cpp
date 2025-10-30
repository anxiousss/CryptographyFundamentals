#include "number_functions.hpp"

namespace number_functions {

     boost::multiprecision::cpp_int NumberTheoryFunctions::gcd(const boost::multiprecision::cpp_int &a,
                                              const boost::multiprecision::cpp_int &b) {
        boost::multiprecision::cpp_int x = a, y = b;
        boost::multiprecision::cpp_int q, r;
        while (true) {
            auto rem = x % y;
            if (rem == 0) return r;
            r = rem;
            x = y;
            y = r;
        }
    }

    std::tuple<boost::multiprecision::cpp_int, boost::multiprecision::cpp_int, boost::multiprecision::cpp_int>
            NumberTheoryFunctions::extended_gcd(const boost::multiprecision::cpp_int &a,
                                                const boost::multiprecision::cpp_int &b) {
        boost::multiprecision::cpp_int r0 = a, r1 = b;
        boost::multiprecision::cpp_int x0 = 1, x1 = 0;
        boost::multiprecision::cpp_int y0 = 0, y1 = 1;

        while (true) {
            boost::multiprecision::cpp_int q = r0 / r1, r2 = r0 % r1, x2 = x0 - q * x1, y2 = y0 - q * y1;
            r0 = r1; r1 = r2; x0 = x1; x1 = x2; y0 = y1; y1 = y2;
            if (r1 == 0) {
                if (r0 < 0) {
                    r0 = -r0;
                    x0 = -x0;
                    y0 = -y0;
                }
                return std::make_tuple(r0, x0, y0);
            }
        }
     }

    boost::multiprecision::cpp_int mod_exp(const boost::multiprecision::cpp_int &base,
                                                  const boost::multiprecision::cpp_int &exp,
                                                  const boost::multiprecision::cpp_int &mod) {
        auto res = base, deg = exp;
        while (deg != 1) {
            if ((deg & 1) == 1) {
                res *= res % mod;
            }
            res *= res;
            deg >>= 1;
        }
        return res;
     }

    boost::multiprecision::cpp_int legendre_symbol(const boost::multiprecision::cpp_int &a,
                                                   const boost::multiprecision::cpp_int &b) {

     }

    boost::multiprecision::cpp_int jacobi_symbol(const boost::multiprecision::cpp_int &a,
                                                 const boost::multiprecision::cpp_int &p) {
         if (a % p == 0) {
             return 0;
         }

     }
}

