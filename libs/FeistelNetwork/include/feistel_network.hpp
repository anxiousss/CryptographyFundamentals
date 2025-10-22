#pragma once

#include "symmetric_context.hpp"


namespace feistel_network {
    class FeistelNetwork {
    private:
        std::vector<std::byte> key;
        size_t rounds;
        std::shared_ptr<symmetric_context::RoundKeyGeneration> round_key_generator;
        std::shared_ptr<symmetric_context::EncryptionTransformation> encryption_transformer;

    public:
        FeistelNetwork(std::vector<std::byte> key_, size_t rounds_,
                       std::shared_ptr<symmetric_context::RoundKeyGeneration> round_key_generator_,
                       std::shared_ptr<symmetric_context::EncryptionTransformation> encryption_transformer_);

        std::vector<std::byte> encrypt(const std::vector<std::byte>& block) const;

        std::vector<std::byte> decrypt(const std::vector<std::byte>& block) const;
    };
}