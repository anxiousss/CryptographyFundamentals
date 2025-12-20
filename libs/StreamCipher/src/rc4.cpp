#include "rc4.hpp"

namespace stream_cipher {

    RC4::RC4(const std::vector<std::byte> &key_): key(key_) {}

    void RC4::key_scheduling() {
        for (size_t i = 0; i < 256; ++i) {
            permutation[i] = i;
        }

        size_t key_length = key.size(), j = 0;
        for (size_t i = 0; i < 256; ++i) {
            j = (j + permutation[i] + static_cast<size_t>(key[i % key_length])) % 256;
            std::swap(permutation[i], permutation[j]);
        }

        k = 0, l = 0;
    }

    std::byte RC4::PRGA() {
        k = (k + 1) % 256;
        l = (l + permutation[k]) % 256;
        std::swap(permutation[k], permutation[l]);
        return static_cast<std::byte>(permutation[(permutation[k] + permutation[l]) % 256]);
    }

    std::future<std::vector<std::byte>> RC4::encrypt(const std::vector<std::byte> &data) {
        return std::async(std::launch::async, [this, data]() -> std::vector<std::byte> {
            key_scheduling();
            std::lock_guard<std::mutex> lock(mutex);
            if (data.empty()) return data;

            size_t data_size = data.size();
            std::vector<std::byte> ciphertext(data_size);
            for (size_t i = 0; i < data_size; ++i) {
                std::byte K = PRGA();
                ciphertext[i] = data[i] ^ K;
            }

            return ciphertext;
        });
    }

    std::future<std::vector<std::byte>> RC4::decrypt(const std::vector<std::byte> &data) {
        return std::async(std::launch::async, [this, data]() -> std::vector<std::byte> {
            std::lock_guard<std::mutex> lock(mutex);
            key_scheduling();
            if (data.empty()) return data;

            size_t data_size = data.size();
            std::vector<std::byte> plaintext(data_size);
            for (size_t i = 0; i < data_size; ++i) {
                std::byte K = PRGA();
                plaintext[i] = data[i] ^ K;
            }

            return plaintext;
        });
    }

    std::future<void>
    RC4::encrypt(const std::filesystem::path &input_file, std::optional<std::filesystem::path> &output_file) {
        return std::async(std::launch::async, [this, input_file, output_file]() {
            std::lock_guard<std::mutex> lock(mutex);

            key_scheduling();
            if (!std::filesystem::exists(input_file)) {
                throw std::runtime_error("Input file does not exist: " + input_file.string());
            }

            std::filesystem::path actual_output_path = output_file.value_or(
                    input_file.parent_path() / (input_file.stem().string() + "_encrypted" + input_file.extension().string()));
            std::filesystem::create_directories(actual_output_path.parent_path());

            std::ifstream in_file(input_file, std::ios::binary);
            std::ofstream out_file(actual_output_path, std::ios::binary);

            if (!in_file.is_open()) {
                throw std::runtime_error("Cannot open input file: " + input_file.string());
            }
            if (!out_file.is_open()) {
                throw std::runtime_error("Cannot open output file: " + actual_output_path.string());
            }


            in_file.seekg(0, std::ios::end);
            size_t file_size = in_file.tellg();
            in_file.seekg(0, std::ios::beg);

            if (file_size == 0) {
                out_file.write(reinterpret_cast<const char*>(""), 0);
                std::cout << "Encrypted empty file: " << input_file << " -> " << actual_output_path << std::endl;
                return;
            }

            char c;
            while (in_file.get(c)) {
                std::byte key_byte = this->PRGA();
                std::byte processed_byte = static_cast<std::byte>(c) ^ key_byte;
                out_file.put(static_cast<char>(processed_byte));
            }

            std::cout << "File encrypted: " << input_file << " -> " << actual_output_path << std::endl;
        });
    }

    std::future<void> RC4::decrypt(const std::filesystem::path& input_file,
                                                std::optional<std::filesystem::path>& output_file) {
        return std::async(std::launch::async, [this, input_file, output_file]() {
            std::lock_guard<std::mutex> lock(mutex);

            key_scheduling();
            if (!std::filesystem::exists(input_file)) {
                throw std::runtime_error("Input file does not exist: " + input_file.string());
            }

            std::string stem = input_file.stem().string();
            if (stem.length() > 10 && stem.substr(stem.length() - 10) == "_encrypted") {
                stem = stem.substr(0, stem.length() - 10);
            }
            std::filesystem::path actual_output_path = output_file.value_or(
                    input_file.parent_path() / (stem + "_decrypted" + input_file.extension().string()));
            std::filesystem::create_directories(actual_output_path.parent_path());

            std::ifstream in_file(input_file, std::ios::binary);
            std::ofstream out_file(actual_output_path, std::ios::binary);

            if (!in_file.is_open() || !out_file.is_open()) {
                throw std::runtime_error("Cannot open input or output file");
            }


            in_file.seekg(0, std::ios::end);
            size_t file_size = in_file.tellg();
            in_file.seekg(0, std::ios::beg);

            if (file_size == 0) {
                std::cout << "Input file is empty: " << input_file << std::endl;
                return;
            }

            char c;
            while (in_file.get(c)) {
                std::byte key_byte = this->PRGA();
                std::byte processed_byte = static_cast<std::byte>(c) ^ key_byte;
                out_file.put(static_cast<char>(processed_byte));
            }


            std::cout << "File decrypted: " << input_file << " -> " << actual_output_path << std::endl;
        });
    }
}