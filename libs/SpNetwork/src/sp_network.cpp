#include "sp_network.hpp"

namespace sp_network {
    SpNetwork::SpNetwork(std::vector<std::byte> key_, size_t rounds_, size_t block_size_,
                         std::shared_ptr<symmetric_context::RoundKeyGeneration> round_key_generator_,
                         std::shared_ptr<symmetric_context::SubstitutionLayer> sub_layer_,
                         std::shared_ptr<symmetric_context::PermutationLayer> permut_layer_): key(key_), rounds(rounds_),
                         block_size(block_size_),round_key_generator(round_key_generator_), sub_layer(sub_layer_),
                         permut_layer(permut_layer_){round_keys = round_key_generator->key_extension(key_, rounds_);}

    std::vector<std::byte> SpNetwork::encrypt(const std::vector<std::byte> &block) const {
        if (block.size() != block_size)
            throw std::runtime_error("Размер блока не соответствует алгоритму.");

        auto state = bits_functions::xor_vectors(block, round_keys[0], block_size);

        for (size_t i = 1; i < rounds; ++i) {
            state = sub_layer->forward(state);
            state = permut_layer->forward(state);
            state = bits_functions::xor_vectors(state, round_keys[i], block_size);
        }
        state = sub_layer->forward(state);
        return bits_functions::xor_vectors(state, round_keys[rounds], block_size);
    }

    std::vector<std::byte> SpNetwork::decrypt(const std::vector<std::byte> &block) const {
        auto state = bits_functions::xor_vectors(block, round_keys[rounds], block_size);
        state = sub_layer->inverse(state);

        for (size_t i = rounds - 1; i >= 1; --i) {
            state = bits_functions::xor_vectors(state, round_keys[i], block_size);
            state = permut_layer->inverse(state);
            state = sub_layer->inverse(state);
        }

        return bits_functions::xor_vectors(state, round_keys[0], block_size);
    }
}