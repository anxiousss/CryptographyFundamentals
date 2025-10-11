    #pragma once

#include <bitset>
#include <iostream>
#include <cstddef>
#include <vector>

std::ostream& operator<<(std::ostream& os, std::byte b);

void set_eldest_bit(std::byte& b, size_t n, bool value);

bool get_eldest_bit(std::byte b, size_t n);

bool get_younger_bit(std::byte b, size_t n);

void set_younger_bit(std::byte& b, size_t n, bool value);

std::vector<std::byte> xor_vectors(const std::vector<std::byte>& a, const std::vector<std::byte>& b, size_t size);