#include "des.hpp"

void print_byte_vector(const std::vector<std::byte>& data) {
    std::cout << "Vector size: " << data.size() << " [";
    for (size_t i = 0; i < std::min(data.size(), size_t(10)); ++i) {
        std::cout << std::hex << static_cast<int>(data[i]) << " ";
    }
    if (data.size() > 10) std::cout << "...";
    std::cout << "]" << std::dec << std::endl;
}

namespace des {

    std::vector<std::vector<std::byte>>
    DesRoundKeyGeneration::key_extension(const std::vector<std::byte> &key, size_t rounds) {
        std::vector<std::byte> extended_key;
        if (key.size() == 7) {
            extended_key = bits_functions::key_extension(key, block_size);
        }
        else {
            std::copy(key.begin(), key.end(), std::back_inserter(extended_key));
        }
        auto pc1_permutation = bits_functions::bits_permutation(extended_key,
                                                                PC1,bits_functions::PermutationRule::ELDEST_ONE_BASED);
        std::vector<std::vector<std::byte>> round_keys;
        round_keys.reserve(rounds);


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

    std::vector<std::byte> FeistelTransformation::encrypt(const std::vector<std::byte> &block,
                                                          const std::vector<std::byte> &round_key) {
        if (block.size() != 4 || round_key.size() != 6) {
            throw std::invalid_argument("Feistel: Invalid block or key size");
        }

        auto expanded_block = bits_functions::expansion_e(block);
        auto xored_block = bits_functions::xor_vectors(expanded_block, round_key, 6);
        auto six_bit_blocks = bits_functions::convert_8blocks_to_6blocks(xored_block);
        std::vector<std::byte> s_box_output(4, std::byte{0});

        for (int i = 0; i < 8; i++) {
            uint8_t six_bits = static_cast<uint8_t>(six_bit_blocks[i]);

            uint8_t row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01);
            uint8_t col = (six_bits & 0x1E) >> 1;

            uint8_t s_box_value = S_BLOCKS[i][row][col];

            int output_byte = i / 2;
            int output_shift = (i % 2 == 0) ? 4 : 0;
            s_box_output[output_byte] |= std::byte(s_box_value) << output_shift;
        }

        return bits_functions::bits_permutation(s_box_output, P_BLOCK, bits_functions::PermutationRule::ELDEST_ONE_BASED);
    }

    DES::DES(const std::vector<std::byte> &key_, std::shared_ptr<DesRoundKeyGeneration> des_round_key_generation,
             std::shared_ptr<FeistelTransformation> feistel_transformation) : key(key_),
             feistel_network(std::move(key_), rounds, des_round_key_generation,
                             feistel_transformation) {}

    void DES::set_key(const std::vector<std::byte> &key) {
        this->key = key;
    }

    std::vector<std::byte> DES::encrypt(const std::vector<std::byte> &block) {
        auto IP_permutaion= bits_functions::bits_permutation(block, IP,
                                                             bits_functions::PermutationRule::ELDEST_ONE_BASED);
        auto cycle_block = feistel_network.encrypt(IP_permutaion);
        return bits_functions::bits_permutation(cycle_block, IP_INV,
                                                bits_functions::PermutationRule::ELDEST_ONE_BASED);
    }

    std::vector<std::byte> DES::decrypt(const std::vector<std::byte> &block) {
        auto IP_permutaion= bits_functions::bits_permutation(block, IP,
                                                             bits_functions::PermutationRule::ELDEST_ONE_BASED);
        auto cycle_block = feistel_network.decrypt(IP_permutaion);
        return bits_functions::bits_permutation(cycle_block, IP_INV,
                                                bits_functions::PermutationRule::ELDEST_ONE_BASED);
    }

    size_t DES::get_block_size() {
        return block_size;
    }
}

