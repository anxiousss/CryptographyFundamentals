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
        size_t msg_bits = n_msg * 8;

        size_t output_bits = IP.size();
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

    std::vector<std::byte> add_number_to_bytes(const std::vector<std::byte> &data, uint64_t number) {
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

    std::vector<std::byte> add_byte_vectors(const std::vector<std::byte> &vec1, const std::vector<std::byte> &vec2) {
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

    std::byte add_odd_bit(std::byte &b) {
        int count = 0;
        for (int i = 7; i >= 1; --i) {
            count += (std::to_integer<unsigned int>(b) >> i) & 1;
        }
        if (count % 2 == 0) {
            b |= std::byte{0b00000001};
        } else {
            b &= std::byte{0b11111110};
        }

        return b;
    }

    std::vector<std::byte> key_extension(const std::vector<std::byte> &data, size_t block_size) {
        std::vector<std::byte> result_data;
        std::byte b{0};

        size_t j = 0;
        for (size_t i = 0; i < data.size() * block_size; ++i) {
            if (j == 7) {
                add_odd_bit(b);
                result_data.push_back(b);
                j = 0;
                b = std::byte{0};
            }

            bool bit = get_eldest_bit(data[i / 8], i % 8);
            set_eldest_bit(b, j, bit);
            ++j;
        }
        result_data.push_back(b);
        return result_data;
    }

    void left_shift_28bit(std::vector<std::byte> &data, int shift) {
        if (data.size() != 4) {
            throw std::invalid_argument("Data must be 4 bytes for 28-bit value");
        }

        uint32_t val = 0;
        for (int i = 0; i < 28; ++i) {
            bool bit = bits_functions::get_eldest_bit(data[i / 8], i % 8);
            val = (val << 1) | (bit ? 1 : 0);
        }

        val = ((val << shift) | (val >> (28 - shift))) & 0x0FFFFFFF;

        for (int i = 27; i >= 0; --i) {
            bool bit = (val >> i) & 1;
            bits_functions::set_eldest_bit(data[(27 - i) / 8], (27 - i) % 8, bit);
        }
    }

    std::vector<std::byte> expansion_e(const std::vector<std::byte>& input_32bit) {
        if (input_32bit.size() != 4) {
            throw std::invalid_argument("Expansion E requires 32-bit input (4 bytes)");
        }

        std::vector<std::byte> result(6, std::byte{0});

        std::vector<int> E_TABLE = {
                32,  1,  2,  3,  4,  5,
                4,  5,  6,  7,  8,  9,
                8,  9, 10, 11, 12, 13,
                12, 13, 14, 15, 16, 17,
                16, 17, 18, 19, 20, 21,
                20, 21, 22, 23, 24, 25,
                24, 25, 26, 27, 28, 29,
                28, 29, 30, 31, 32,  1
        };

        for (size_t i = 0; i < E_TABLE.size(); ++i) {
            int source_bit = E_TABLE[i] - 1;
            int source_byte = source_bit / 8;
            int source_bit_in_byte = 7 - (source_bit % 8);

            bool bit_value = (std::to_integer<uint8_t>(input_32bit[source_byte]) >> source_bit_in_byte) & 1;

            int target_byte = i / 8;
            int target_bit_in_byte = 7 - (i % 8);

            if (bit_value) {
                result[target_byte] |= std::byte(1) << target_bit_in_byte;
            }
        }

        return result;
    }

    std::vector<std::byte> convert_8blocks_to_6blocks (const std::vector<std::byte>& input_48bit) {
        if (input_48bit.size() != 6) {
            throw std::runtime_error("Input must be 6 bytes (48 bits)");
        }

        std::vector<std::byte> output(8, std::byte{0});

        for (int i = 0; i < 8; i++) {
            int start_bit = i * 6;
            uint8_t six_bits = 0;

            for (int j = 0; j < 6; j++) {
                int bit_pos = start_bit + j;
                int byte_idx = bit_pos / 8;
                int bit_in_byte = 7 - (bit_pos % 8);

                bool bit = (std::to_integer<uint8_t>(input_48bit[byte_idx]) >> bit_in_byte) & 1;
                six_bits = (six_bits << 1) | (bit ? 1 : 0);
            }

            output[i] = static_cast<std::byte>(six_bits);
        }

        return output;
    }


    std::vector<std::byte> random_bytes_vector(size_t size_vector) {
        std::vector<std::byte> res(size_vector);

        std::random_device rd;
        std::uniform_int_distribution<unsigned short> dist(0, 255);

        for(size_t i = 0; i < size_vector; ++i) {
            res[i] = static_cast<std::byte>(dist(rd));
        }
        return res;
    }



    std::vector<std::byte> I2OSP(uint64_t x, size_t output_len) {
        if (x >= (1ULL << (8 * output_len))) {
            throw std::invalid_argument("Integer too large for the specified output length");
        }

        std::vector<std::byte> result(output_len, std::byte{0});

        for (size_t i = 0; i < output_len; i++) {
            result[output_len - 1 - i] = static_cast<std::byte>(x & 0xFF);
            x >>= 8;
        }

        return result;
    }
    std::ostream &operator<<(std::ostream &os, std::byte b) {
        return os << std::bitset<8>(std::to_integer<int>(b));
    }
}