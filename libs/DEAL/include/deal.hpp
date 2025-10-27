#include "symmetric_context.hpp"
#include "feistel_network.hpp"
#include "des.hpp"

namespace deal {
    const size_t block_size = 16;
    const std::vector<std::byte> k = {std::byte{0x12},
                                      std::byte{0x34},
                                      std::byte{0x56},
                                      std::byte{0x78},
                                      std::byte{0x90},
                                      std::byte{0xAB},
                                      std::byte{0xCD},
                                      std::byte{0xEF}};
    class DealRoundKeyGeneration: public symmetric_context::RoundKeyGeneration {
        std::vector<std::vector<std::byte>> key_extension(const std::vector<std::byte> &key, size_t rounds) override;
    };

    class DEAL: public symmetric_context::SymmetricAlgorithm {
    private:
        feistel_network::FeistelNetwork feistel_network;
        std::vector<std::byte> key;
    public:
        DEAL(const std::vector<std::byte>& key, std::shared_ptr<DealRoundKeyGeneration> deal_round_key_generation);
        void set_key(const std::vector<std::byte> &key) override;
        std::vector<std::byte> encrypt(const std::vector<std::byte> &block) override;
        std::vector<std::byte> decrypt(const std::vector<std::byte> &block) override;
        size_t get_block_size() override;
    };
}