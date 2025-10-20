#include "feistel_network.hpp"

namespace feistel_network {

    FeistelNetwork::FeistelNetwork(std::vector<std::byte> key_, size_t rounds_,
                                   std::shared_ptr<symmetrical_context::RoundKeyGeneration> round_key_generator_,
                                   std::shared_ptr<symmetrical_context::EncryptionTransformation> encryption_transformer_):
                                   key(std::move(key_)), rounds(rounds_), round_key_generator(round_key_generator_),
                                   encryption_transformer(encryption_transformer_) {}

    std::vector<std::byte> FeistelNetwork::encrypt(const std::vector<std::byte> &block) const {
        auto keys = round_key_generator->key_extension(key, rounds);
        std::vector<std::byte> L(block.begin(), block.begin() + block.size() / 2);
        std::vector<std::byte> R(block.begin() + block.size() / 2, block.end());

        for (size_t i = 0; i < rounds; ++i) {
            auto encrypted_R = encryption_transformer->encrypt(R, keys[i]);
            auto xor_block = bits_functions::xor_vectors(L, encrypted_R, block.size() / 2);
            L = R;
            R = xor_block;
        }

        std::vector<std::byte> result_block;
        result_block.resize(block.size());
        std::copy(L.begin(), L.end(), std::back_inserter(result_block));
        std::copy(R.begin(), R.end(), std::back_inserter(result_block));

        return result_block;
    }

    std::vector<std::byte> FeistelNetwork::decrypt(const std::vector<std::byte> &block) const {
        auto keys = round_key_generator->key_extension(key, rounds);
        std::vector<std::byte> L(block.begin(), block.begin() + block.size() / 2);
        std::vector<std::byte> R(block.begin() + block.size() / 2, block.end());

        for (int i = static_cast<int>(rounds) - 1; i >= 0; --i) {
            auto encrypted_L = encryption_transformer->encrypt(R, keys[i]);
            auto xor_block = bits_functions::xor_vectors(R, encrypted_L, block.size() / 2);

            R = L;
            L = xor_block;
        }
        std::vector<std::byte> result_block;
        result_block.resize(block.size());
        std::copy(R.begin(), R.end(), std::back_inserter(result_block));
        std::copy(L.begin(), L.end(), std::back_inserter(result_block));

        return result_block;
    }
}