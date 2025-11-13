#include "triple_des.hpp"

namespace triple_des {

    TripleDes::TripleDes(AlgorithmType type_, const std::vector<std::byte> &key_) : type(type_) {
        if (key_.size() != 21 && key_.size() != 24) {
            throw std::invalid_argument("TripleDES key must be 21 or 24 bytes");
        }

        size_t key_part_size = key_.size() / 3;

        key1.assign(key_.begin(), key_.begin() + key_part_size);
        key2.assign(key_.begin() + key_part_size, key_.begin() + 2 * key_part_size);
        key3.assign(key_.begin() + 2 * key_part_size, key_.end());

        auto key_gen = std::make_shared<des::DesRoundKeyGeneration>();
        auto feistel = std::make_shared<des::FeistelTransformation>();

        this->des1 = std::make_shared<des::DES>(key1, key_gen, feistel);
        this->des2 = std::make_shared<des::DES>(key2, key_gen, feistel);
        this->des3 = std::make_shared<des::DES>(key3, key_gen, feistel);
    }

    void TripleDes::set_key(const std::vector<std::byte> &key_) {
        if (key_.size() != 21 && key_.size() != 24) {
            throw std::invalid_argument("TripleDES key must be 21 or 24 bytes");
        }

        size_t key_part_size = key_.size() / 3;

        key1.assign(key_.begin(), key_.begin() + key_part_size);
        key2.assign(key_.begin() + key_part_size, key_.begin() + 2 * key_part_size);
        key3.assign(key_.begin() + 2 * key_part_size, key_.end());

        des1->set_key(key1);
        des2->set_key(key2);
        des3->set_key(key3);
    }

    std::vector<std::byte> TripleDes::encrypt(const std::vector<std::byte> &block) {
        if (block.size() != block_size) {
            throw std::invalid_argument("TripleDES block size must be 8 bytes");
        }

        std::vector<std::byte> result;

        switch (type) {
            case AlgorithmType::EEE:
                result = des1->encrypt(block);
                result = des2->encrypt(result);
                result = des3->encrypt(result);
                break;

            case AlgorithmType::EDE:
                result = des3->encrypt(block);
                result = des2->decrypt(result);
                result = des1->encrypt(result);
                break;
        }

        return result;
    }

    std::vector<std::byte> TripleDes::decrypt(const std::vector<std::byte> &block) {
        if (block.size() != block_size) {
            throw std::invalid_argument("TripleDES block size must be 8 bytes");
        }

        std::vector<std::byte> result;

        switch (type) {
            case AlgorithmType::EEE:
                result = des3->decrypt(block);
                result = des2->decrypt(result);
                result = des1->decrypt(result);
                break;

            case AlgorithmType::EDE:
                result = des1->decrypt(block);
                result = des2->encrypt(result);
                result = des3->decrypt(result);
                break;
        }

        return result;
    }

    size_t TripleDes::get_block_size() {
        return block_size;
    }
}