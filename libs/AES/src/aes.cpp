#include "aes.hpp"

namespace aes {

    std::vector<std::vector<std::byte>>
    AesRoundKeyGeneration::key_extension(const std::vector<std::byte> &key, size_t rounds) {

    }

    std::vector<std::byte> AesSubstitutionLayer::forward(const std::vector<std::byte> &block) {

    }

    std::vector<std::byte> AesSubstitutionLayer::inverse(const std::vector<std::byte> &block) {

    }

    std::vector<std::byte> AesPermutationLayer::forward(const std::vector<std::byte> &block) {

    }

    std::vector<std::byte> AesPermutationLayer::inverse(const std::vector<std::byte> &block) {

    }
}