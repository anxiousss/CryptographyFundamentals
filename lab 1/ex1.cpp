#include "utility.hpp"


std::vector<std::byte> bits_permutation(std::vector<std::byte> msg, const std::vector<unsigned int>& IP,
                                        bool indexing_rule, bool staring_bit_number) {

    size_t n_msg = msg.size();
    size_t bits_number = n_msg * 8;
    std::vector<std::byte> permutation(n_msg, std::byte{0});

    for (int i = 0; i < bits_number; ++i) {
        auto& b = permutation[i / 8];
        if (indexing_rule) {
            unsigned int bit_pos = (IP[i] % 8) - (staring_bit_number ? 1 : 0);
            auto value = get_eldest_bit(msg[IP[i] / 8], bit_pos);
            set_eldest_bit(b, i % 8, value);
        } else {
            unsigned int bit_pos = (IP[i] % 8) - (staring_bit_number ? 1 : 0);
            auto value = get_younger_bit(msg[IP[i] / 8], bit_pos);
            set_younger_bit(b, i % 8, value);
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