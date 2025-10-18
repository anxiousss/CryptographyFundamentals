#include "bits_functions.hpp"

namespace bits_functions {


    void set_eldest_bit(std::byte &b, size_t n, bool value) {
        b = (b & ~(std::byte(0x80) >> n)) | (std::byte(value ? 0x80 : 0x00) >> n);
    }

    bool get_eldest_bit(std::byte b, size_t n) {
        return (b & (std::byte(0x80) >> n)) != std::byte(0);
    }

    bool get_younger_bit(std::byte b, size_t n) {
        return (b & (std::byte(1) << n)) != std::byte(0);
    }

    void set_younger_bit(std::byte &b, size_t n, bool value) {
        b = (b & ~(std::byte(1) << n)) | (std::byte(value) << n);
    }

    std::vector<std::byte> bits_permutation(const std::vector<std::byte> &msg, const std::vector<unsigned int> &IP,
                                            PermutationRule rule) {

        size_t n_msg = msg.size();
        size_t bits_number = n_msg * 8;
        std::vector<std::byte> permutation(n_msg, std::byte{0});

        bool eldest_first = (rule == PermutationRule::ELDEST_ZERO_BASED ||
                             rule == PermutationRule::ELDEST_ONE_BASED);
        bool one_based = (rule == PermutationRule::ELDEST_ONE_BASED ||
                          rule == PermutationRule::YOUNGEST_ONE_BASED);


        for (size_t i = 0; i < bits_number; ++i) {
            unsigned int source_index = IP[i];

            if (one_based) {
                if (source_index == 0 || source_index > bits_number) {
                    throw std::out_of_range("IP index out of range with 1-based numbering");
                }
                source_index -= 1;
            } else if (source_index >= bits_number) {
                throw std::out_of_range("IP index out of range with 0-based numbering");
            }

            auto &target_byte = permutation[i / 8];
            unsigned int target_bit_pos = i % 8;

            unsigned int source_byte_index = source_index / 8;
            unsigned int source_bit_pos = source_index % 8;

            bool bit_value;
            if (eldest_first) {
                bit_value = get_eldest_bit(msg[source_byte_index], source_bit_pos);
                set_eldest_bit(target_byte, target_bit_pos, bit_value);
            } else {
                bit_value = get_younger_bit(msg[source_byte_index], source_bit_pos);
                set_younger_bit(target_byte, target_bit_pos, bit_value);
            }
        }

        return permutation;
    }

    std::vector<std::byte> xor_vectors(const std::vector<std::byte> &a, const std::vector<std::byte> &b, size_t size) {
        if (a.size() < size || b.size() < size) {
            throw std::invalid_argument("Input vectors are too small for XOR operation");
        }

        std::vector<std::byte> result;
        result.reserve(size);

        for (size_t i = 0; i < size; ++i) {
            result.push_back(a[i] ^ b[i]);
        }

        return result;
    }

    std::vector<std::byte> add_number_to_bytes(const std::vector<std::byte>& data, uint64_t number) {
        std::vector<std::byte> result = data;

        uint64_t carry = number;
        for (int i = result.size() - 1; i >= 0 && carry > 0; --i) {
            uint64_t current_value = static_cast<uint64_t>(result[i]);
            uint64_t sum = current_value + carry;
            result[i] = static_cast<std::byte>(sum & 0xFF);
            carry = sum >> 8;
        }

        return result;
    }

    std::vector<std::byte> add_byte_vectors(const std::vector<std::byte>& vec1, const std::vector<std::byte>& vec2) {
        size_t max_size = std::max(vec1.size(), vec2.size());
        std::vector<std::byte> result(max_size, std::byte{0});

        uint16_t carry = 0;

        for (int i = max_size - 1; i >= 0; --i) {
            uint8_t val1 = (i < static_cast<int>(vec1.size())) ? static_cast<uint8_t>(vec1[i]) : 0;
            uint8_t val2 = (i < static_cast<int>(vec2.size())) ? static_cast<uint8_t>(vec2[i]) : 0;

            uint16_t sum = val1 + val2 + carry;
            result[i] = static_cast<std::byte>(sum & 0xFF);
            carry = sum >> 8;
        }

        return result;
    }

    std::vector<std::byte> key_extension(const std::vector<std::byte>& data) {

    }

}

std::ostream &operator<<(std::ostream &os, std::byte b) {
    return os << std::bitset<8>(std::to_integer<int>(b));
}