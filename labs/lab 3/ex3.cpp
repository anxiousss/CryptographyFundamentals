#include "rijndael.hpp"

int main() {
    std::byte mod{0x1B};
    rijndael::Operations operations(mod, 16);
    std::vector<std::byte> key_128 = {std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33},
                                      std::byte{0x44}, std::byte{0x55}, std::byte{0x66}, std::byte{0x77},
                                      std::byte{0x88}, std::byte{0x99}, std::byte{0xaa}, std::byte{0xbb},
                                      std::byte{0xcc}, std::byte{0xdd}, std::byte{0xee}, std::byte{0xff}};

    std::vector<std::byte> plaintext = {std::byte{0x00}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
                                        std::byte{0x04}, std::byte{0x05}, std::byte{0x06}, std::byte{0x07},
                                        std::byte{0x08}, std::byte{0x09}, std::byte{0x0a}, std::byte{0x0b},
                                        std::byte{0x0c}, std::byte{0x0d}, std::byte{0x0e}, std::byte{0x0f}};

    bits_functions::print_byte_vector(plaintext);
    rijndael::Rijndael rijndael_alg(key_128, 16, mod);

    auto cipher = rijndael_alg.encrypt(plaintext);
    bits_functions::print_byte_vector(cipher);
    auto decrpyted = rijndael_alg.decrypt(cipher);
    bits_functions::print_byte_vector(decrpyted);

}