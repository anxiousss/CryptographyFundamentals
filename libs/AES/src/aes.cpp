#include "aes.hpp"

namespace aes {

    std::vector<std::vector<std::byte>>
    AesRoundKeyGeneration::key_extension(const std::vector<std::byte> &key, size_t rounds) {
        std::vector<std::vector<std::byte>> w;
        if (key.size() == 16) {
            w = bits_functions::split_vector_accumulate(key, {4, 4, 4, 4});
            for (size_t i = 4; i < 44; ++i) {
                if (i % 4 == 0) {
                    std::vector<std::byte> rot_word = bits_functions::left_circular_shift(w[i - 1]);
                    std::vector<std::byte> sub_block = AesSubstitutionLayer::sub(rot_word);
                    std::vector<std::byte> rcon_word = {RCON[(i / 4) - 1], std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};
                    std::vector<std::byte> g = bits_functions::xor_vectors(sub_block, rcon_word, 4);
                    w.push_back(bits_functions::xor_vectors(w[i - 4], g, 4));
                } else {
                    w.push_back(bits_functions::xor_vectors(w[i - 4], w[i - 1], 4));
                }
            }
        } else if (key.size() == 24) {
            w = bits_functions::split_vector_accumulate(key, {4, 4, 4, 4, 4, 4});
            for (size_t i = 6; i < 52; ++i) {
                if (i % 6 == 0) {
                    std::vector<std::byte> rot_word = bits_functions::left_circular_shift(w[i - 1]);
                    std::vector<std::byte> sub_block =  AesSubstitutionLayer::sub(rot_word);
                    std::vector<std::byte> rcon_word = {RCON[(i / 6) - 1], std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};
                    std::vector<std::byte> g = bits_functions::xor_vectors(sub_block, rcon_word, 4);
                    w.push_back(bits_functions::xor_vectors(w[i - 6], g, 4));
                } else {
                    w.push_back(bits_functions::xor_vectors(w[i - 6], w[i - 1], 4));
                }
            }
        } else if (key.size() == 32) {
            w = bits_functions::split_vector_accumulate(key, {4, 4, 4, 4, 4, 4, 4, 4});
            for (size_t i = 6; i < 60; ++i) {
                if (i % 8 == 0) {
                    std::vector<std::byte> rot_word = bits_functions::left_circular_shift(w[i - 1]);
                    std::vector<std::byte> sub_block =  AesSubstitutionLayer::sub(rot_word);
                    std::vector<std::byte> rcon_word = {RCON[(i / 8) - 1], std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};
                    std::vector<std::byte> g = bits_functions::xor_vectors(sub_block, rcon_word, 4);
                    w.push_back(bits_functions::xor_vectors(w[i - 8], g, 4));
                } else if (i % 8 == 4){
                    std::vector<std::byte> sub_block =  AesSubstitutionLayer::sub(w[i - 1]);
                    w.push_back(bits_functions::xor_vectors(w[i - 8], sub_block, 4));

                } else {
                    w.push_back(bits_functions::xor_vectors(w[i - 8], w[i - 1], 4));
                }
            }
        } else {
            throw std::invalid_argument("Invalid key size for AES.");
        }
        return w;
    }

    std::vector<std::byte> AesSubstitutionLayer::forward(const std::vector<std::byte> &block) {

    }

    std::vector<std::byte> AesSubstitutionLayer::inverse(const std::vector<std::byte> &block) {

    }

    std::vector<std::byte> AesSubstitutionLayer::sub(const std::vector<std::byte> &block) {
        std::vector<std::byte> sub_byte_block;
        sub_byte_block.reserve(block.size());
        for (auto& byte: block) {
            sub_byte_block.push_back(SBOX[static_cast<uint8_t>(byte)]);
        }
        return sub_byte_block;
    }

    std::vector<std::byte> AesPermutationLayer::forward(const std::vector<std::byte> &block) {

    }

    std::vector<std::byte> AesPermutationLayer::inverse(const std::vector<std::byte> &block) {

    }
}