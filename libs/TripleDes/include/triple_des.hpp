#pragma once

#include <cstddef>
#include <vector>
#include <memory>
#include <stdexcept>
#include "des.hpp"
#include "symmetric_context.hpp"

namespace triple_des {
    enum class AlgorithmType {
        EEE,  // Encrypt-Encrypt-Encrypt
        EDE,  // Encrypt-Decrypt-Encrypt
    };

    const size_t block_size = 8;

    class TripleDes : public symmetric_context::SymmetricAlgorithm {
    private:
        AlgorithmType type;
        std::vector<std::byte> key1, key2, key3;
        std::shared_ptr<des::DES> des1, des2, des3;

    public:
        TripleDes(AlgorithmType type_, const std::vector<std::byte>& key_);
        void set_key(const std::vector<std::byte> &key) override;
        std::vector<std::byte> encrypt(const std::vector<std::byte> &block) override;
        std::vector<std::byte> decrypt(const std::vector<std::byte> &block) override;
        size_t get_block_size() override;
    };
}