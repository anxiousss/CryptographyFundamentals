#include "rijndael.hpp"

int main() {
    std::byte mod{0x1B};
    std::byte a{0x10};
    galois_fields::GaloisField::print_element({std::byte{0x01}, mod});
    galois_fields::GaloisField::print_element({a});
    std::byte inv = galois_fields::GaloisField::multiplicative_inverse(a, mod);
    galois_fields::GaloisField::print_element({inv});
    galois_fields::GaloisField::print_element({galois_fields::GaloisField::multiply(a, inv, mod)});

}