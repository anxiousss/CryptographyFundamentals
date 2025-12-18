#include <vector>
#include <cstddef>
#include <cstring>
#include <bit>
#include <map>
#include "bits_functions.hpp"
#include "number_functions.hpp"

namespace galois_fields {

    class GaloisField {
    public:
//        static std::byte mod_exp(const std::byte& base, int exp, const std::byte& mod);

        static std::byte add(const std::byte& first, const std::byte& second);

//        static std::byte  multiply(const std::byte& a,
//                                                const std::byte& b, const std::byte& mod);

//        static std::byte  multiplicative_inverse(const std::byte& a,
//                                                              const std::byte& mod);

//        static bool is_polynom_irreducible(const std::byte& polynomial);

//        static void print_table();

        static void print_element(const std::vector<std::byte>& el);

        static std::pair<std::byte, std::byte>
        divide(const std::vector<std::byte>& a, const std::byte& b);

//        static std::map<size_t, std::vector<std::vector<std::byte>>> find_irreducible_polynomials();
    };
}