#include "des.hpp"

namespace des {

    std::vector<std::vector<std::byte>>
    DesRoundKeyGeneration::key_extension(const std::vector<std::byte> &key, size_t rounds) {
        if (key.size() != 7) {
            throw std::runtime_error("Key must 56 bits");
        }

        std::vector<std::vector<std::byte>> round_keys;
        round_keys.reserve(rounds);
        std::vector<std::byte> extened_key = bits_functions::key_extension(key, block_size);
        auto pc1_permutation = bits_functions::bits_permutation(extened_key, PC1, bits_functions::PermutationRule::ELDEST_ONE_BASED);

        std::vector<std::byte> C_i(4, std::byte{0});
        std::vector<std::byte> D_i(4, std::byte{0});

        for (size_t i = 0; i < 28; ++i) {
            bool bit = bits_functions::get_eldest_bit(pc1_permutation[i / 8], i % 8);
            bits_functions::set_eldest_bit(C_i[i / 8], i % 8, bit);
        }

        for (size_t i = 0; i < 28; ++i) {
            bool bit = bits_functions::get_eldest_bit(pc1_permutation[(i + 28) / 8], (i + 28) % 8);
            bits_functions::set_eldest_bit(D_i[i / 8], i % 8, bit);
        }

        for (size_t round = 0; round < rounds; ++round) {
            bits_functions::left_shift_28bit(C_i, shift_table[round]);
            bits_functions::left_shift_28bit(D_i, shift_table[round]);

            std::vector<std::byte> CD(7, std::byte{0});
            for (int i = 0; i < 28; ++i) {
                bool bit = bits_functions::get_eldest_bit(C_i[i / 8], i % 8);
                bits_functions::set_eldest_bit(CD[i / 8], i % 8, bit);
            }
            for (int i = 0; i < 28; ++i) {
                bool bit = bits_functions::get_eldest_bit(D_i[i / 8], i % 8);
                bits_functions::set_eldest_bit(CD[(i + 28) / 8], (i + 28) % 8, bit);
            }

            std::vector<std::byte> round_key = bits_functions::bits_permutation(
                    CD, PC2, bits_functions::PermutationRule::ELDEST_ONE_BASED);

            round_keys.push_back(round_key);
        }
        return round_keys;
    }

    std::byte FeistelTransformation::s_block_transformation(std::byte &b, size_t s_block_index) {
        uint8_t input = static_cast<uint8_t>(b);

        uint8_t row = ((input & 0x20) >> 4) | ((input & 0x01) >> 0);
        uint8_t col = (input & 0x1E) >> 1;

        uint8_t value = S_BLOCKS[s_block_index][row][col];
        return static_cast<std::byte>(value << 4);
    }

    std::vector<std::byte> FeistelTransformation::encrypt(const std::vector<std::byte> &block,
                                                          const std::vector<std::byte> &round_key) {

        if (block.size() != 4 || round_key.size() != 6) {
            throw std::invalid_argument("Invalid block or key size");
        }

        std::vector<std::byte> expanded_block = bits_functions::expansion_e(block);
        expanded_block = bits_functions::xor_vectors(expanded_block, round_key, round_key.size());
        std::vector<std::byte> b_vector1 = bits_functions::convert_8blocks_to_6blocks(expanded_block);

        std::vector<std::byte> b_vector2;
        b_vector2.reserve(8);
        for (size_t i = 0; i < 8; ++i) {
            b_vector2.push_back(s_block_transformation(b_vector1[i], i));
        }


        std::vector<std::byte> result(4, std::byte{0});
        for (size_t i = 0; i < 8; ++i) {
            size_t byte_index = i / 2;
            uint8_t value = static_cast<uint8_t>(b_vector2[i]);

            if (i % 2 == 0) {
                result[byte_index] |= static_cast<std::byte>(value << 4);
            } else {
                result[byte_index] |= static_cast<std::byte>(value);
            }
        }

        return bits_functions::bits_permutation(result, P_BLOCK, bits_functions::PermutationRule::ELDEST_ONE_BASED);
    }

    DES::DES(const std::vector<std::byte> &key_, std::shared_ptr<DesRoundKeyGeneration> des_round_key_generation,
             std::shared_ptr<FeistelTransformation> feistel_transformation) : key(key_),
             feistel_network(key_, rounds, des_round_key_generation,
                             feistel_transformation) {}

    void DES::set_key(const std::vector<std::byte> &key) {
        this->key = key;
    }

    std::vector<std::byte> DES::encrypt(const std::vector<std::byte> &block) {
        auto IP_permutaion= bits_functions::bits_permutation(block, IP, bits_functions::PermutationRule::ELDEST_ONE_BASED);
        auto cycle_block = feistel_network.encrypt(IP_permutaion);
        return bits_functions::bits_permutation(cycle_block, IP_INV, bits_functions::PermutationRule::ELDEST_ONE_BASED);
    }

    std::vector<std::byte> DES::decrypt(const std::vector<std::byte> &block) {
        auto IP_permutaion= bits_functions::bits_permutation(block, IP, bits_functions::PermutationRule::ELDEST_ONE_BASED);
        auto cycle_block = feistel_network.decrypt(IP_permutaion);
        return bits_functions::bits_permutation(cycle_block, IP_INV, bits_functions::PermutationRule::ELDEST_ONE_BASED);
    }

    size_t DES::get_block_size() {
        return block_size;
    }
}

