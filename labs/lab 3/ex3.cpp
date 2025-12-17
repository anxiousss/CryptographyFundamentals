#include "galois_fields.hpp"

int main() {
    std::vector<std::byte> el = {std::byte{0b11101010}, std::byte{0x00}};
    std::vector<std::byte> mod = {std::byte{0b11001000}, std::byte{0x00}};
    galois_fields::GaloisField::print_element(el);
    galois_fields::GaloisField::print_element(mod);
    galois_fields::GaloisField::print_element(galois_fields::GaloisField::divide(el, mod));
    //galois_fields::GaloisField::print_table();
}