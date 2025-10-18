#include "des.hpp"

namespace des {

    std::vector<std::vector<std::byte>>
    DesRoundKeyGeneration::key_extension(const std::vector<std::byte> &key, size_t rounds) {
        if (key.size() != 7) {
            throw std::runtime_error("Key must 56 bits");
        }

        std::vector<std::vector<std::byte>> round_keys;
        round_keys.resize(rounds);
        for (size_t i = 0; i < rounds; ++i) {
            std::vector<std::byte> round_key;

        }
    }
}