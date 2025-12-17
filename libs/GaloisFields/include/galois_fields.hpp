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
        static std::vector<std::byte> add(const std::vector<std::byte>& a, const std::vector<std::byte>& b);
        static std::vector<std::byte>  multiply(const std::vector<std::byte>& a, const std::vector<std::byte>& b, const std::vector<std::byte>& mod);
        static std::vector<std::byte>  multiplicative_inverse(const std::vector<std::byte>& a, const std::vector<std::byte>& mod);
        static void print_table();
        static void print_element(const std::vector<std::byte>& el);
        static std::vector<std::byte> divide(const std::vector<std::byte>& a, const std::vector<std::byte>& b);
        static std::map<size_t, std::vector<std::vector<std::byte>>> find_irreducible_polynomials();
    };
}