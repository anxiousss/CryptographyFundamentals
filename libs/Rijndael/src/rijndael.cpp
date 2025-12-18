#include "rijndael.hpp"
/*
namespace rijndael {
    std::array<std::byte, 256> generate_sbox(std::vector<std::byte> polynomial) {
        std::array<std::byte, 256> SBOX;
        for (size_t i = 0; i < 256; ++i) {
            std::byte b = std::byte(bits_functions::reverse_bits(static_cast<uint8_t>(i)));
            b = galois_fields::GaloisField::multiplicative_inverse({b}, polynomial)[0];
            std::byte byte = galois_fields::GaloisField::add({b},
                                                   {bits_functions::cyclic_shift_left(b, 1)})[0];
            std::cout << byte << std::endl;
            byte = galois_fields::GaloisField::add({byte},
                                                   {bits_functions::cyclic_shift_left(b, 2)})[0];
            byte = galois_fields::GaloisField::add({byte},
                                                   {bits_functions::cyclic_shift_left(b, 3)})[0];
            byte = galois_fields::GaloisField::add({byte},
                                                   {bits_functions::cyclic_shift_left(b, 4)})[0];
            byte = galois_fields::GaloisField::add({byte},{std::byte(0x63)})[0];
            SBOX[i] = byte;
        }
        return SBOX;
    }

    void print_box(std::array<std::byte, 256> box) {
        std::cout << std::hex << std::uppercase << std::setfill('0');
        std::cout << "      ";
        for (int i = 0; i < 16; ++i) {
            std::cout << "  " << std::setw(2) << i;
        }
        std::cout << "\n";
        std::cout << "      ";
        for (int i = 0; i < 16; ++i) {
            std::cout << "----";
        }
        std::cout << "-\n";
        for (int row = 0; row < 16; ++row) {
            std::cout << std::setw(2) << row << "  |";
            for (int col = 0; col < 16; ++col) {
                int index = row * 16 + col;
                std::cout << "  " << std::setw(2)
                          << static_cast<int>(box[index]);
            }
            std::cout << std::endl;
        }

        std::cout << std::dec << std::setfill(' ') << std::nouppercase;
    }

    RijndaelRoundKeyGenerator::RijndaelRoundKeyGenerator(size_t block_size_, const std::vector<std::byte>& polynomial):
        block_size(block_size_) {
        Rcon.reserve(20);
        Rcon.push_back(std::vector{std::byte{0b10000000}, std::byte{0x00}});

        for (int i = 1; i < 20; ++i) {
            Rcon.push_back(galois_fields::GaloisField::multiply(Rcon[i - 1], {std::byte{0b01000000}, std::byte{0x00}}, polynomial));
        }
        for (int i = 0; i < Rcon.size(); ++i) {
            bits_functions::print_le(Rcon[i]);
        }
    }

    std::vector<std::vector<std::byte>> RijndaelRoundKeyGenerator::key_extension(const std::vector<std::byte> &key, size_t rounds) {

    }

    std::vector<std::byte>
    RijndaelRoundTransformation::encrypt(const std::vector<std::byte> &block, const std::vector<std::byte> &round_key) {}

    std::vector<std::byte>
    RijndaelRoundTransformation::decrypt(const std::vector<std::byte> &block, const std::vector<std::byte> &round_key) {}

    RijndaelRoundTransformation::RijndaelRoundTransformation(std::vector<std::byte> polynomial) {
        SBOX = generate_sbox(polynomial);
    }

    Rijndael::Rijndael(std::vector<std::byte> &key_, size_t block_size_, size_t index_):
        key(std::move(key_)), block_size(block_size_), polynominal(irreducible_polynomials[index_]) {}

    Rijndael::Rijndael(std::vector<std::byte> &key_, size_t block_size_, std::vector<std::byte> polynominal_):
        key(std::move(key_)), block_size(block_size_) {

        if (!galois_fields::GaloisField::is_polynom_irreducible(polynominal_))
            throw std::invalid_argument("Mod polynom is not irreducible.");

        this->polynominal = polynominal_;
    }

    void Rijndael::set_key(const std::vector<std::byte> &key_) {}

    std::vector<std::byte> Rijndael::encrypt(const std::vector<std::byte> &block) {}

    std::vector<std::byte> Rijndael::decrypt(const std::vector<std::byte> &block) {}

    size_t Rijndael::get_block_size() {}


}*/