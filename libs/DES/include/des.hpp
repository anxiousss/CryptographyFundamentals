#pragma once

#include "symmetric_algorithm.hpp"
#include "feistel_network.hpp"

namespace des {
    class DesRoundKeyGeneration: public symmetrical_context::RoundKeyGeneration {
    public:
        std::vector<std::vector<std::byte>> key_extension(const std::vector<std::byte> &key, size_t rounds) override;
    };

    class FeistelTransformation: public symmetrical_context::EncryptionTransformation {
    public:
        std::vector<std::byte> encrypt(const std::vector<std::byte> &block,
                                       const std::vector<std::byte> &round_key) const override;
    };

    class DES: public symmetrical_context::SymmetricAlgorithm {
    private:
        size_t block_size;
        feistel_network::FeistelNetwork feistel_network;
    public:
        void set_key(const std::vector<std::byte> &key) override;
        std::vector<std::byte> encrypt(const std::vector<std::byte> &block) override;
        std::vector<std::byte> decrypt(const std::vector<std::byte> &block) override;
        size_t get_block_size() override;
    };
}