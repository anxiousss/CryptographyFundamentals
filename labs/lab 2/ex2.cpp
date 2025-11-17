#include <random>
#include "rsa.hpp"

void print_byte_vector(const std::vector<std::byte>& data) {
    std::cout << "Vector size: " << data.size() << " [";
    for (size_t i = 0; i < std::min(data.size(), size_t(10)); ++i) {
        std::cout << std::hex << static_cast<int>(data[i]) << " ";
    }
    if (data.size() > 10) std::cout << "...";
    std::cout << "]" << std::dec << std::endl;
}

std::vector<std::byte> random_bytes_vector(size_t size_vector) {
    std::vector<std::byte> res;
    std::random_device device;
    std::mt19937 gen(device());
    std::uniform_int_distribution<unsigned char> dist(0, 255);
    for(size_t i = 0; i < size_vector; ++i) {
        res.push_back(std::byte{dist(gen)});
    }
    return res;
}


int main() {
    std::cout << rsa::Wieners_attack(17993, 90581) << std::endl;
}