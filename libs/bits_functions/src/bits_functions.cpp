#include "bits_functions.hpp"

namespace bits_functions {

    uint8_t reverse_bits(uint8_t b){
        b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
        b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
        b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
        return b;
    };

    void print_byte_vector(const std::vector<std::byte>& data) {
        std::cout << "Vector size: " << data.size() << " [";
        for (size_t i = 0; i < std::min(data.size(), size_t(100)); ++i) {
            std::cout << std::hex << static_cast<int>(data[i]) << " ";
        }
        if (data.size() > 100) std::cout << "...";
        std::cout << "]" << std::dec << std::endl;
    }

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

    int polynomial_degree(uint16_t poly) {
        if (poly == 0) return -1;
        return std::bit_width(poly) - 1;
    }

    std::pair<uint16_t, uint16_t> divide_with_quotient(uint16_t poly1, uint16_t poly2) {
        if (poly2 == 0) {
            throw std::invalid_argument("Division by zero polynomial");
        }

        int deg1 = polynomial_degree(poly1);
        int deg2 = polynomial_degree(poly2);

        uint16_t quotient = 0;
        uint16_t remainder = poly1;

        while (deg1 >= deg2 && remainder != 0) {
            int shift = deg1 - deg2;

            quotient |= (1 << shift);

            remainder ^= (poly2 << shift);

            deg1 = polynomial_degree(remainder);
        }

        return {quotient, remainder};
    }


    uint16_t bytes_to_uint16(const std::vector<std::byte>& data) {
        if (data.size() < sizeof(uint16_t)) {
            throw std::invalid_argument("Not enough bytes");
        }
        uint16_t result = 0;
        int index =  data.size() * 8 - 1;
        for (int i = index; i > -1; --i) {
            auto bit = bits_functions::get_younger_bit(data[(index - i) / 8], i % 8);
            result += bit * std::pow(2, i);
        }
        return result;
    }

    std::byte uint16t_to_byte(uint16_t value) {
        return static_cast<std::byte>(value);
    }

    std::vector<std::byte> uint16_to_bytes(uint16_t value) {
        std::vector<std::byte> result;

        result.push_back(std::byte{(static_cast<uint8_t>(value & 0xFF))});
        result.push_back(std::byte{(static_cast<uint8_t>((value >> 8) & 0xFF))});

        return result;
    }

    std::byte cyclic_shift_left(const std::byte &first, size_t amount) {
        uint8_t value = static_cast<uint8_t>(first);
        amount %= 8;
        uint8_t result = (value << amount) | (value >> (8 - amount));
        return static_cast<std::byte>(result);
    }

    std::vector<std::byte> cyclic_left_row_shift(std::vector<std::byte>& row, size_t amount) {
        if (amount == 0)
            return row;

        size_t n_rows = row.size();
        amount %= n_rows;
        for (size_t i = 0; i < amount; ++i) {
            row.push_back(row[0]);
            row.erase(row.begin());
        }

        return row;
    }

    std::vector<std::byte> cyclic_right_row_shift(std::vector<std::byte>& row, size_t amount) {
        if (amount == 0)
            return row;

        size_t n_rows = row.size();
        amount %= n_rows;
        for (size_t i = 0; i < amount; ++i) {
            row.insert(row.begin(), row[row.size() - 1]);
            row.erase(row.end());
        }

        return row;
    }

    std::vector<std::byte> rotation_word(std::vector<std::byte>& word) {
        return cyclic_left_row_shift(word, 1);
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

    std::vector<std::byte> left_circular_shift(const std::vector<std::byte>& data) {
        std::vector<std::byte> new_data(data.begin() + 1, data.end());
        auto zero_el = data.front();
        new_data.push_back(zero_el);
        return new_data;
    }

    std::vector<std::byte> expansion_e(const std::vector<std::byte>& input_32bit) {
        if (input_32bit.size() != 4) {
            throw std::invalid_argument("Expansion E requires 32-bit input (4 bytes)");
        }

        std::vector<std::byte> result(6, std::byte{0});

        std::array<int, 48> E_TABLE = {
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
}

std::ostream &operator<<(std::ostream &os, std::byte b) {
    return os << std::bitset<8>(std::to_integer<int>(b));
}
