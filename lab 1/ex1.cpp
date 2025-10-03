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

std::vector<std::byte> bits_permutation(std::vector<std::byte>& msg, const std::vector<unsigned int>& IP,
                        bool indexing_rule, bool staring_bit_number) {

    // если starting_bit_number = true, то вычитаем везде 1 из позиции
    size_t n_msg = msg.size();
    size_t bits_number = n_msg * 8;
    std::vector<std::byte> permutation{n_msg};
    // void (*set_bit)(std::byte& b, int n, bool value);
    if (indexing_rule) {
        // set_bit = set_eldest_bit;
        for (size_t i = 0; i < bits_number; ++i) {
            // permutation[IP[i] % n_msg][i] = msg[i % n_msg][IP[i]]
            auto b = permutation[IP[i] % n_msg];
            set_eldest_bit(b, i % n_msg - staring_bit_number,
                           get_eldest_bit(msg[i % n_msg], IP[i] % n_msg - staring_bit_number));
        }
    }

    return permutation;
}



int main() {
    std::vector<std::byte> msg(2);
    msg[0] = std::byte{10};
    msg[1] = std::byte{12};
    std::cout << msg[0] << ' ' << msg[1] << std::endl;
    const std::vector<unsigned int> IP = {15, 14, 2, 7, 6, 9, 1, 3, 10, 11, 9, 4, 5, 8, 13, 12, 16};
    bool rule = true, bit_number = true;

    auto P = bits_permutation(msg, IP, rule, bit_number);
    std::cout << P[0] << ' ' << P[1];

    return 0;
}