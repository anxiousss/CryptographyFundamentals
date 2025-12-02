#include "symmetric_context.hpp"

namespace sp_network {
    class SpNetwork {
    private:
        std::vector<std::byte> key;
        size_t rounds;
        size_t block_size;
        std::vector<std::vector<std::byte>> round_keys;
        std::shared_ptr<symmetric_context::RoundKeyGeneration> round_key_generator;
        std::shared_ptr<symmetric_context::SubstitutionLayer> sub_layer;
        std::shared_ptr<symmetric_context::PermutationLayer> permut_layer;

    public:
        SpNetwork(std::vector<std::byte> key_, size_t rounds_, size_t block_size,
                  std::shared_ptr<symmetric_context::RoundKeyGeneration> round_key_generator_,
                  std::shared_ptr<symmetric_context::SubstitutionLayer> sub_layer_,
                  std::shared_ptr<symmetric_context::PermutationLayer> permut_layer_);

        std::vector<std::byte> encrypt(const std::vector<std::byte>& block) const;

        std::vector<std::byte> decrypt(const std::vector<std::byte>& block) const;
    };
}