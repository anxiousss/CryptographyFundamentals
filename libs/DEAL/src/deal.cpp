#include "deal.hpp"

namespace deal {

    size_t set_rounds(const std::vector<std::byte>& key) {
        if (key.size() == 16 || key.size() == 24) return 6;
        if (key.size() == 32) return 8;
        throw std::runtime_error("Invalid key size.");
    }

    std::vector<std::byte> DealRoundKeyGeneration::magic_64bit_number(unsigned int i) {
        int bit_pos = i - 1;

        std::vector<std::byte> result(8, std::byte{0});

        int byte_index = 7 - (bit_pos / 8);
        int bit_in_byte = bit_pos % 8;

        result[byte_index] = std::byte{1} << (7 - bit_in_byte);
        return result;
    }

    std::vector<std::vector<std::byte>> DealRoundKeyGeneration::key_extension(const std::vector<std::byte> &key,
                                                                              size_t rounds) {
        std::shared_ptr<des::DES> des_alg = std::make_shared<des::DES>(k, std::make_shared<des::DesRoundKeyGeneration>(),
                std::make_shared<des::FeistelTransformation>());
        std::vector<std::byte> K1{8};
        std::vector<std::byte> K2{8};
        if (key.size() == 16) {
            std::copy(key.begin(), key.begin() + key.size() / 2, K1.begin());
            std::copy(key.begin() + key.size() / 2, key.end(), K2.begin());
            std::vector<std::byte> RK1 = des_alg->encrypt(K1);
            std::vector<std::byte> RK2 = des_alg->encrypt(bits_functions::xor_vectors(K2,
                                                                                     RK1, K2.size()));
            std::vector<std::byte> RK3 = des_alg->encrypt(bits_functions::xor_vectors(
                    bits_functions::xor_vectors(K1, magic_64bit_number(1),
                                                K1.size()), RK2, RK2.size()));
            std::vector<std::byte> RK4 = des_alg->encrypt(bits_functions::xor_vectors(
                    bits_functions::xor_vectors(K2, magic_64bit_number(2),
                                                K2.size()), RK3, RK3.size()));
            std::vector<std::byte> RK5 = des_alg->encrypt(bits_functions::xor_vectors(
                    bits_functions::xor_vectors(K1, magic_64bit_number(4),
                                                K1.size()), RK4, RK4.size()));
            std::vector<std::byte> RK6 = des_alg->encrypt(bits_functions::xor_vectors(
                    bits_functions::xor_vectors(K2, magic_64bit_number(8),
                                                K2.size()), RK5, RK5.size()));

            return std::vector<std::vector<std::byte>>{RK1, RK2, RK3, RK4, RK5, RK6};
        } else if (key.size() == 24) {
            std::vector<std::byte> K3{8};
            std::copy(key.begin(), key.begin() + key.size() / 3, K1.begin());
            std::copy(key.begin() + key.size() / 3, key.begin() + 2 * (key.size() / 3), K2.begin());
            std::copy(key.begin() + 2 * (key.size() / 3), key.end(), K3.begin());
            std::vector<std::byte> RK1 = des_alg->encrypt(K1);
            std::vector<std::byte> RK2 = des_alg->encrypt(bits_functions::xor_vectors(K2,
                                                                                      RK1, K2.size()));
            std::vector<std::byte> RK3 = des_alg->encrypt(bits_functions::xor_vectors(K3,
                                                                                      RK2, K3.size()));
            std::vector<std::byte> RK4 = des_alg->encrypt(bits_functions::xor_vectors(
                    bits_functions::xor_vectors(K1, magic_64bit_number(1),
                                                K1.size()), RK3, RK3.size()));
            std::vector<std::byte> RK5 = des_alg->encrypt(bits_functions::xor_vectors(
                    bits_functions::xor_vectors(K2, magic_64bit_number(2),
                                                K2.size()), RK4, RK4.size()));
            std::vector<std::byte> RK6 = des_alg->encrypt(bits_functions::xor_vectors(
                    bits_functions::xor_vectors(K3, magic_64bit_number(4),
                                                K3.size()), RK5, RK5.size()));

            return std::vector<std::vector<std::byte>>{RK1, RK2, RK3, RK4, RK5, RK6};
        } else {
            std::vector<std::byte> K3{8};
            std::vector<std::byte> K4{8};
            std::copy(key.begin(), key.begin() + key.size() / 4, K1.begin());
            std::copy(key.begin() + key.size() / 4, key.begin() + 2 * (key.size() / 4), K2.begin());
            std::copy(key.begin() + 2 * (key.size() / 4), key.begin() + 3 * (key.size() / 4), K3.begin());
            std::copy(key.begin() + 3 * (key.size() / 4), key.end(), K4.begin());
            std::vector<std::byte> RK1 = des_alg->encrypt(K1);
            std::vector<std::byte> RK2 = des_alg->encrypt(bits_functions::xor_vectors(K2,
                                                                                      RK1, K2.size()));
            std::vector<std::byte> RK3 = des_alg->encrypt(bits_functions::xor_vectors(K3,
                                                                                      RK2, K3.size()));
            std::vector<std::byte> RK4 = des_alg->encrypt(bits_functions::xor_vectors(K4,
                                                                                      RK3, K4.size()));
            std::vector<std::byte> RK5 = des_alg->encrypt(bits_functions::xor_vectors(
                    bits_functions::xor_vectors(K1, magic_64bit_number(1),
                                                K1.size()), RK4, RK4.size()));
            std::vector<std::byte> RK6 = des_alg->encrypt(bits_functions::xor_vectors(
                    bits_functions::xor_vectors(K2, magic_64bit_number(2),
                                                K2.size()), RK5, RK5.size()));
            std::vector<std::byte> RK7 = des_alg->encrypt(bits_functions::xor_vectors(
                    bits_functions::xor_vectors(K3, magic_64bit_number(4),
                                                K3.size()), RK6, RK6.size()));
            std::vector<std::byte> RK8 = des_alg->encrypt(bits_functions::xor_vectors(
                    bits_functions::xor_vectors(K4, magic_64bit_number(8),
                                                K4.size()), RK7, RK7.size()));
            return std::vector<std::vector<std::byte>>{RK1, RK2, RK3, RK4, RK5, RK6, RK7, RK8};
        }
    }

    std::vector<std::byte> DesTransformation::encrypt(const std::vector<std::byte> &block,
                                                      const std::vector<std::byte> &round_key) {
        des::DES des_alg(round_key, std::make_shared<des::DesRoundKeyGeneration>(),
                std::make_shared<des::FeistelTransformation>());
        return des_alg.encrypt(block);
    }

    DEAL::DEAL(const std::vector<std::byte> &key_, std::shared_ptr<DealRoundKeyGeneration> deal_round_key_generation,
               std::shared_ptr<DesTransformation> des_transformation): key(std::move(key_)), feistel_network(key_,
               set_rounds(key_), deal_round_key_generation,
               des_transformation) {}

    void DEAL::set_key(const std::vector<std::byte> &key) {
        this->key = key;
    }

    std::vector<std::byte> DEAL::encrypt(const std::vector<std::byte> &block) {
        return feistel_network.encrypt(block);
    }

    std::vector<std::byte> DEAL::decrypt(const std::vector<std::byte> &block) {
        return feistel_network.decrypt(block);
    }

    size_t DEAL::get_block_size() {
        return block_size;
    }
}