#include "galois_fields.hpp"

int main() {
    // galois_fields::GaloisField::print_table();
    std::vector<std::byte> a = {std::byte{0b11011000}, std::byte{0b10000000}};
    std::vector<std::byte> b = {std::byte{0b11010000}, std::byte{0b00000000}};
    galois_fields::GaloisField::print_element(a);
    galois_fields::GaloisField::print_element(b);
    auto [remainder, quotient] = galois_fields::GaloisField::divide(a, b);
    galois_fields::GaloisField::print_element(remainder);
    galois_fields::GaloisField::print_element(quotient);
    auto inverse = galois_fields::GaloisField::multiplicative_inverse(b, a);
    galois_fields::GaloisField::print_element(inverse);
    galois_fields::GaloisField::print_element(galois_fields::GaloisField::multiply(b, inverse, a));
}