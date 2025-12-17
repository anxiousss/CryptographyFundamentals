#include "galois_fields.hpp"

int main() {
    /*std::vector<std::byte> a = {std::byte{0b10110011}, std::byte{0x00}};
    std::vector<std::byte> b = {std::byte{0b11011110}, std::byte{0x00}};
    std::vector<std::byte> mod = {std::byte{0b11011000}, std::byte{0b10000000}};
    galois_fields::GaloisField::print_element(a);
    galois_fields::GaloisField::print_element(b);
    galois_fields::GaloisField::print_element(mod);
    auto res = galois_fields::GaloisField::multiply(a, b, mod);
    galois_fields::GaloisField::print_element(res);*/
    std::vector<std::byte> mod = {std::byte{0b11011000}, std::byte{0b10000000}};
    auto n = number_functions::NumberTheoryFunctions::bytes_to_cpp_int(mod);
    std::cout << n;
}