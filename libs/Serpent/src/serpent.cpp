#include "serpent.hpp"
#include <algorithm>

namespace serpent {

    void apply_sbox_bitsliced(uint32_t block[4], int sbox_num, bool inverse) {

        const uint8_t* table = inverse ? INV_S_BOX[sbox_num] : S_BOX[sbox_num];
        uint32_t result[4] = {0, 0, 0, 0};

        for (int bit_pos = 0; bit_pos < 32; bit_pos++) {
            uint8_t input_nibble =
                    ((block[0] >> bit_pos) & 1) |
                    (((block[1] >> bit_pos) & 1) << 1) |
                    (((block[2] >> bit_pos) & 1) << 2) |
                    (((block[3] >> bit_pos) & 1) << 3);

            uint8_t output_nibble = table[input_nibble];

            if (output_nibble & 0x01) result[0] |= (1 << bit_pos);
            if (output_nibble & 0x02) result[1] |= (1 << bit_pos);
            if (output_nibble & 0x04) result[2] |= (1 << bit_pos);
            if (output_nibble & 0x08) result[3] |= (1 << bit_pos);
        }

        for (int i = 0; i < 4; i++) {
            block[i] = result[i];
        }
    }

    void apply_sbox_to_block(uint32_t block[4], int sbox_num) {
        apply_sbox_bitsliced(block, sbox_num, false);
    }

    void apply_inverse_sbox_to_block(uint32_t block[4], int sbox_num) {
        apply_sbox_bitsliced(block, sbox_num, true);
    }

    std::vector<std::vector<std::byte>>
    SerpentKeyGeneration::key_extension(const std::vector<std::byte>& key, size_t rounds) {
        std::vector<std::byte> k = key;
        if (k.size() < 32) {

            k.push_back(std::byte{0x80});
            while (k.size() < 32) {
                k.insert(k.begin(), std::byte{0x00});
            }
        }

        std::vector<uint32_t> w(132);

        for (int i = 0; i < 8; i++) {
            w[i] = bits_functions::bytes_to_uint32(
                    {k.begin() + i * 4, k.begin() + (i + 1) * 4}, true);
        }

        const uint32_t phi = 0x9E3779B9;
        for (int i = 8; i < 132; i++) {
            uint32_t val = w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ phi ^ static_cast<uint32_t>(i);
            w[i] = bits_functions::rotate_left(val, 11);
        }

        std::vector<std::vector<std::byte>> roundKeys(33, std::vector<std::byte>(16));

        for (int i = 0; i < 33; i++) {
            uint32_t block[4] = {
                    w[4*i + 8],
                    w[4*i + 8 + 1],
                    w[4*i + 8 + 2],
                    w[4*i + 8 + 3]
            };

            int sbox_idx = (3 - (i % 8) + 8) % 8;

            apply_sbox_bitsliced(block, sbox_idx, false);

            std::vector<std::byte> temp_k(16);
            for (int j = 0; j < 4; j++) {
                auto b = bits_functions::uint32_to_bytes(block[j], true);
                std::copy(b.begin(), b.end(), temp_k.begin() + j*4);
            }

            roundKeys[i] = bits_functions::bits_permutation<128>(
                    temp_k, Serpent::IP, bits_functions::PermutationRule::YOUNGEST_ZERO_BASED);
        }

        return roundKeys;
    }

    Serpent::Serpent(std::vector<std::byte> key_) : key(std::move(key_)) {
        serpent_key_generation = std::make_shared<SerpentKeyGeneration>();
        round_keys = serpent_key_generation->key_extension(key,32);
    }

    void Serpent::set_key(const std::vector<std::byte> &key_) {
        this->key = key_;
        round_keys = serpent_key_generation->key_extension(key, 32);
    }

    void Serpent::linear_transform(uint32_t X[4]) {
        X[0] = bits_functions::rotate_left(X[0], 13);
        X[2] = bits_functions::rotate_left(X[2], 3);
        X[1] = X[1] ^ X[0] ^ X[2];
        X[3] = X[3] ^ X[2] ^ (X[0] << 3);
        X[1] = bits_functions::rotate_left(X[1], 1);
        X[3] = bits_functions::rotate_left(X[3], 7);
        X[0] = X[0] ^ X[1] ^ X[3];
        X[2] = X[2] ^ X[3] ^ (X[1] << 7);
        X[0] = bits_functions::rotate_left(X[0], 5);
        X[2] = bits_functions::rotate_left(X[2], 22);
    }


    void Serpent::inverse_linear_transform(uint32_t X[4]) {
        X[2] = bits_functions::rotate_right(X[2], 22);
        X[0] = bits_functions::rotate_right(X[0], 5);

        uint32_t original_X2 = X[2] ^ X[3] ^ (X[1] << 7);
        uint32_t original_X0 = X[0] ^ X[1] ^ X[3];

        X[3] = bits_functions::rotate_right(X[3], 7);
        X[1] = bits_functions::rotate_right(X[1], 1);


        X[3] = X[3] ^ original_X2 ^ (original_X0 << 3);
        X[1] = X[1] ^ original_X0 ^ original_X2;

        X[2] = original_X2;
        X[0] = original_X0;
        X[2] = bits_functions::rotate_right(X[2], 3);
        X[0] = bits_functions::rotate_right(X[0], 13);
    }

    std::vector<std::byte> Serpent::encrypt(const std::vector<std::byte> &block) {
        if (block.size() != 16) {
            throw std::invalid_argument("Block must be 128 bits (16 bytes)");
        }

        auto state = bits_functions::bits_permutation<128>(
                block, IP, bits_functions::PermutationRule::YOUNGEST_ZERO_BASED);

        uint32_t X[4];
        for (int i = 0; i < 4; i++) {
            X[i] = bits_functions::bytes_to_uint32(
                    {state.begin() + i*4, state.begin() + (i+1)*4}, true);
        }

        for (int round = 0; round < 32; round++) {
            uint32_t Kr[4];
            for (int i = 0; i < 4; i++) {
                Kr[i] = bits_functions::bytes_to_uint32(
                        {round_keys[round].begin() + i*4,
                         round_keys[round].begin() + (i+1)*4}, true);
                X[i] ^= Kr[i];
            }

            apply_sbox_to_block(X, round % 8);

            if (round < 31) {
                linear_transform(X);
            } else {
                uint32_t K32[4];
                for (int i = 0; i < 4; i++) {
                    K32[i] = bits_functions::bytes_to_uint32(
                            {round_keys[32].begin() + i*4,
                             round_keys[32].begin() + (i+1)*4}, true);
                    X[i] ^= K32[i];
                }
            }
        }

        std::vector<std::byte> ciphertext(16);
        for (int i = 0; i < 4; i++) {
            auto b = bits_functions::uint32_to_bytes(X[i], true);
            std::copy(b.begin(), b.end(), ciphertext.begin() + i*4);
        }

        return bits_functions::bits_permutation<128>(
                ciphertext, FP, bits_functions::PermutationRule::YOUNGEST_ZERO_BASED);
    }
    std::vector<std::byte> Serpent::decrypt(const std::vector<std::byte> &block) {
        if (block.size() != 16) {
            throw std::invalid_argument("Block must be 128 bits (16 bytes)");
        }

        auto state = bits_functions::bits_permutation<128>(
                block, IP, bits_functions::PermutationRule::YOUNGEST_ZERO_BASED);

        uint32_t X[4];
        for (int i = 0; i < 4; i++) {
            X[i] = bits_functions::bytes_to_uint32(
                    {state.begin() + i*4, state.begin() + (i+1)*4}, true);
        }

        for (int round = 31; round >= 0; round--) {
            if (round == 31) {
                uint32_t K32[4];
                for (int i = 0; i < 4; i++) {
                    K32[i] = bits_functions::bytes_to_uint32(
                            {round_keys[32].begin() + i*4,
                             round_keys[32].begin() + (i+1)*4}, true);
                    X[i] ^= K32[i];
                }
            }
            else if (round < 31) {
                inverse_linear_transform(X);
            }

            apply_inverse_sbox_to_block(X, round % 8);

            uint32_t Kr[4];
            for (int i = 0; i < 4; i++) {
                Kr[i] = bits_functions::bytes_to_uint32(
                        {round_keys[round].begin() + i*4,
                         round_keys[round].begin() + (i+1)*4}, true);
                X[i] ^= Kr[i];
            }
        }

        std::vector<std::byte> plaintext(16);
        for (int i = 0; i < 4; i++) {
            auto b = bits_functions::uint32_to_bytes(X[i], true);
            std::copy(b.begin(), b.end(), plaintext.begin() + i*4);
        }

        return bits_functions::bits_permutation<128>(
                plaintext, FP, bits_functions::PermutationRule::YOUNGEST_ZERO_BASED);
    }

    size_t Serpent::get_block_size() { return 16; }
}