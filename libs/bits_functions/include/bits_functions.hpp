#pragma once

#include <bitset>
#include <iostream>
#include <cstddef>
#include <vector>
#include <array>
#include <bit>
#include <cstdint>
#include <random>

namespace bits_functions {
    enum class PermutationRule {
        ELDEST_ZERO_BASED,
        ELDEST_ONE_BASED,
        YOUNGEST_ZERO_BASED,
        YOUNGEST_ONE_BASED
    };

    uint8_t reverse_bits(uint8_t b);

    void print_byte_vector(const std::vector<std::byte>& data);

    void set_eldest_bit(std::byte &b, size_t n, bool value);

    bool get_eldest_bit(std::byte b, size_t n);

    bool get_younger_bit(std::byte b, size_t n);

    void set_younger_bit(std::byte &b, size_t n, bool value);

    std::vector<std::byte> xor_vectors(const std::vector<std::byte> &a, const std::vector<std::byte> &b, size_t size);

    int polynomial_degree(uint16_t poly);

    std::pair<uint16_t, uint16_t> divide_with_quotient(uint16_t poly1, uint16_t poly2);

    std::byte cyclic_shift_left(const std::byte &first, size_t amount);

    uint16_t bytes_to_uint16(const std::vector<std::byte>& bytes);

    std::vector<std::byte> uint16_to_bytes(uint16_t value);

    std::byte uint16t_to_byte(uint16_t value);

    uint32_t rotate_left(uint32_t x, int n);

    uint32_t rotate_right(uint32_t x, int n);

    std::vector<std::byte> uint32_to_bytes(uint32_t value, bool little_endian = true);

    uint32_t bytes_to_uint32(const std::vector<std::byte>& bytes, bool little_endian = true);

    std::vector<std::byte> cyclic_left_row_shift(std::vector<std::byte>& row, size_t amount);

    std::vector<std::byte> cyclic_right_row_shift(std::vector<std::byte>& row, size_t amount);

    std::vector<std::byte> rotation_word(std::vector<std::byte>& word);

    template<size_t TableSize>
    std::vector<std::byte>
    bits_permutation(const std::vector<std::byte>& msg,
                     const std::array<unsigned int, TableSize>& IP,
                     PermutationRule rule) {

        size_t n_msg = msg.size();
        size_t msg_bits = n_msg * 8;
        size_t output_bits = TableSize;
        size_t output_bytes = (output_bits + 7) / 8;

        std::vector<std::byte> permutation(output_bytes, std::byte{0});

        bool eldest_first = (rule == PermutationRule::ELDEST_ZERO_BASED ||
                             rule == PermutationRule::ELDEST_ONE_BASED);
        bool one_based = (rule == PermutationRule::ELDEST_ONE_BASED ||
                          rule == PermutationRule::YOUNGEST_ONE_BASED);

        for (size_t i = 0; i < output_bits; ++i) {
            unsigned int source_index = IP[i];

            if (one_based) {
                if (source_index == 0 || source_index > msg_bits) {
                    throw std::out_of_range("IP index out of range with 1-based numbering");
                }
                source_index -= 1;
            } else if (source_index >= msg_bits) {
                throw std::out_of_range("IP index out of range with 0-based numbering");
            }

            auto& target_byte = permutation[i / 8];
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
    std::vector<std::byte> add_number_to_bytes(const std::vector<std::byte>& data, uint64_t number);

    std::vector<std::byte> add_byte_vectors(const std::vector<std::byte>& vec1, const std::vector<std::byte>& vec2);

    std::byte add_odd_bit(std::byte& b);

    std::vector<std::byte> key_extension(const std::vector<std::byte>& data, size_t block_size);

    void left_shift_28bit(std::vector<std::byte>& data, int shift);


    std::vector<std::byte> expansion_e(const std::vector<std::byte>& input_32bit);

    std::vector<std::byte> convert_8blocks_to_6blocks(const std::vector<std::byte>& block);

    std::vector<std::byte> random_bytes_vector(size_t size_vector);


    template<typename T, typename... Vectors>
    std::vector<T> concat_vectors(Vectors&&... vectors) {
        std::vector<std::vector<std::remove_cv_t<std::remove_reference_t<T>>>> vecs = {
                std::forward<Vectors>(vectors)...
        };

        std::vector<T> result;
        return std::accumulate(
                vecs.begin(),
                vecs.end(),
                result,
                [](std::vector<T> acc, const std::vector<T>& vec) {
                    acc.insert(acc.end(), vec.begin(), vec.end());
                    return acc;
                });
    }

    template<typename T>
    std::vector<std::vector<T>> split_vector_accumulate(const std::vector<T>& source,
                                                        const std::vector<size_t>& sizes) {
        std::vector<std::vector<T>> result;

        size_t total_size = std::accumulate(sizes.begin(), sizes.end(), 0ull);
        if (total_size != source.size()) {
            throw std::invalid_argument("Total sizes don't match source vector size");
        }

        auto it = source.begin();
        for (size_t size : sizes) {
            result.emplace_back(it, it + size);
            it += size;
        }

        return result;
    }

    std::vector<std::byte> I2OSP(uint64_t x, size_t output_len);
}

std::ostream &operator<<(std::ostream &os, std::byte b);
