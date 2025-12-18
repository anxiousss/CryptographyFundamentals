#include "rijndael.hpp"

int main() {
    std::vector<std::byte> y{std::byte{0b11100010}, std::byte{0b00100101}};
    galois_fields::GaloisField::print_element(y);
}