#include "utility.hpp"

std::ostream& operator<<(std::ostream& os, std::byte b) {
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

std::vector<std::byte> xor_vectors(const std::vector<std::byte>& a, const std::vector<std::byte>& b, size_t size) {
    std::vector<std::byte> result(size);
    for (int i = 0; i < size; ++i) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}