#include <bitset>
#include <iostream>
#include <cstddef>
#include <vector>

std::ostream& operator<<(std::ostream& os, std::byte b)
{
    return os << std::bitset<8>(std::to_integer<int>(b));
}


void set_eldest_bit(std::byte& b, size_t n, bool value) {
    b = (b & ~(std::byte(0x80) >> n)) | (std::byte(value ? 0x80 : 0x00) >> n);
}

bool get_eldest_bit(std::byte b, size_t n) {
    return (b & (std::byte(0x80) >> n)) != std::byte(0);
}

bool get_younger_bit(std::byte b, size_t n) {
    return (b & (std::byte(1) << n)) != std::byte(0);
}

void set_younger_bit(std::byte& b, size_t n, bool value) {
    b = (b & ~(std::byte(1) << n)) | (std::byte(value) << n);
}

std::vector<std::byte> bits_permutation(std::vector<std::byte> msg, const std::vector<unsigned int>& IP,
                        bool indexing_rule, bool staring_bit_number) {

    size_t n_msg = msg.size();
    size_t bits_number = n_msg * 8;
    std::vector<std::byte> permutation{n_msg, std::byte{0}};
    for (int i = 0; i < bits_number; ++i) {
        auto& b = permutation[i / 8];
        if (indexing_rule) {
            auto value = get_eldest_bit(msg[IP[i] / 8], (IP[i] % 8) - staring_bit_number);
            set_eldest_bit(b, i % 8, value);
        } else {
            // std::cout << permutation[0] << ' '  << permutation[1] << std::endl;
            auto value = get_younger_bit(msg[(bits_number - IP[i]) / 8], IP[i] % 8 - staring_bit_number);
            set_younger_bit(b, 7 - i % 8, value);
        }
    }

    return permutation;
}


int main() {
    std::vector<std::byte> msg(2);
    msg[0] = std::byte{10};
    msg[1] = std::byte{14};

    std::cout << msg[0] << ' ' << msg[1] << std::endl;

    std::vector<unsigned int> IP_1 = {15, 14, 2, 7, 6, 1, 3, 10, 11, 9, 4, 5, 8, 13, 12, 16};
    std::vector<unsigned int> IP_2 = {14, 13, 1, 6, 5, 0, 2, 9, 10, 8, 3, 4, 7, 12, 11, 15};
    bool rule = false, bit_number = true;

    auto P_1 = bits_permutation(msg, IP_1, rule, bit_number);
    std::cout << P_1[0] << ' ' << P_1[1] << std::endl;
    auto P_2 = bits_permutation(msg, IP_2, rule, !bit_number);
    std::cout << P_2[0] << ' ' << P_2[1] << std::endl;

    return 0;
}