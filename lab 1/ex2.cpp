#include <vector>
#include <future>
#include <optional>
#include <any>
#include <filesystem>
#include <memory>
#include <algorithm>
#include <thread>
#include <mutex>
#include <iostream>
#include <cassert>

#include "bits_functions.hpp"

enum class EncryptionModes {
    ECB = 0,
    CBC,
    PCBC,
    CFB,
    OFB,
    CTR,
    RandomDelta
};

enum class PaddingModes {
    Zeros = 0,
    ANSIX_923,
    PKCS7,
    ISO_10126
};

class RoundKeyGeneration {
public:
    virtual ~RoundKeyGeneration() = default;
    virtual std::vector<std::vector<std::byte>> key_extension(const std::vector<std::byte>& key) = 0;
};

class EncryptionTransformation {
public:
    virtual ~EncryptionTransformation() = default;
    virtual std::vector<std::byte> encrypt(const std::vector<std::byte>& block,
                                           const std::vector<std::byte>& round_key) const = 0;
};


class SymmetricEncryption {
public:
    virtual ~SymmetricEncryption() = default;
    //virtual void set_round_keys(const std::vector<std::vector<std::byte>>& round_keys) = 0;
    virtual std::vector<std::byte> encrypt(const std::vector<std::byte>& block) = 0;
    virtual std::vector<std::byte> decrypt(const std::vector<std::byte>& block) = 0;
    virtual size_t get_block_size() = 0;
};

class TestEncyption: public SymmetricEncryption {
    std::vector<std::byte> encrypt(const std::vector<std::byte>& block) override {
        return block;
    }

    std::vector<std::byte> decrypt(const std::vector<std::byte>& block) override {
        return block;
    }
    size_t get_block_size() override{
        return 8;
    }
};

class SymmetricAlgorithm {
private:
    std::vector<std::byte> key;
    EncryptionModes encryption_mode;
    PaddingModes padding_mode;
    std::optional<std::vector<std::byte>> init_vector;
    std::vector<std::any> params;
    std::unique_ptr<SymmetricEncryption> algorithm;

    mutable std::mutex mutex;

public:
    SymmetricAlgorithm(std::vector<std::byte> key_, EncryptionModes encryption_mode_, PaddingModes padding_mode_,
                       std::optional<std::vector<std::byte>> init_vector_ = std::nullopt,
                       std::vector<std::any> params_ = {}, std::unique_ptr<SymmetricEncryption> algorithm_ = nullptr):
                       key(std::move(key_)), encryption_mode(encryption_mode_), padding_mode(padding_mode_),
                       init_vector(std::move(init_vector_)), params(std::move(params_)), algorithm(std::move(algorithm_)) {};

    ~SymmetricAlgorithm() = default;

    std::future<std::vector<std::byte>> encrypt(const std::vector<std::byte>& data);
    std::future<void> encrypt(const std::filesystem::path& input_file, const std::filesystem::path& output_file);

    std::future<std::vector<std::byte>> decrypt(const std::vector<std::byte>& data);
    std::future<void> decrypt(const std::filesystem::path& input_file, const std::filesystem::path& output_file);

public:
    std::vector<std::byte> ECB(const std::vector<std::byte>& data, bool encrypt) {
        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data = data;

        if (encrypt) {
            padding(new_data, data.size() / block_size);
        }

        std::vector<std::thread> threads;

        for (size_t i = 0; i < new_data.size(); i += block_size) {
            threads.emplace_back([&, i, block_size]() {
                std::vector<std::byte> block(
                        new_data.begin() + i,
                        new_data.begin() + std::min(i + block_size, new_data.size())
                );

                std::vector<std::byte> processed_block;
                if (encrypt) {
                    processed_block = this->algorithm->encrypt(block);
                } else {
                    processed_block = this->algorithm->decrypt(block);
                }

                std::copy(processed_block.begin(), processed_block.end(), new_data.begin() + i);
            });
        }

        for (auto& t : threads) {
            t.join();
        }
        return new_data;
    }

    std::vector<std::byte> CBC(std::vector<std::byte>& data, bool encrypt) {
        if (!init_vector.has_value()) {
            throw std::runtime_error("Initialization vector is required for CBC mode");
        }

        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data = data;

        if (encrypt) {
            size_t required_blocks = (data.size() + block_size - 1) / block_size;
            padding(new_data, required_blocks * block_size);
        }

        auto& iv = init_vector.value();

        if (iv.size() < block_size) {
            iv.resize(block_size);
        }

        std::vector<std::byte> previous_block = iv;

        for (size_t i = 0; i < new_data.size(); i += block_size) {
            std::vector<std::byte> current_block(
                    new_data.begin() + i,
                    new_data.begin() + std::min(i + block_size, new_data.size())
            );

            std::vector<std::byte> processed_block;

            if (encrypt) {
                auto xored_block = xor_vectors(current_block, previous_block, block_size);
                processed_block = this->algorithm->encrypt(xored_block);
            } else {
                auto decrypted_block = this->algorithm->decrypt(current_block);
                processed_block = xor_vectors(decrypted_block, previous_block, block_size);
            }

            std::copy(processed_block.begin(), processed_block.end(), new_data.begin() + i);

            if (encrypt) {
                previous_block = processed_block;
            } else {
                previous_block = current_block;
            }
        }

        return new_data;
    }
    std::vector<std::byte> PCBC(const std::vector<std::byte>& data, bool encrypt) {
        if (!init_vector.has_value()) {
            throw std::runtime_error("Initialization vector is required for CBC mode");
        }
        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data = data;

        if (encrypt) {
            size_t required_blocks = (data.size() + block_size - 1) / block_size;
            padding(new_data, required_blocks * block_size);
        }

        auto& iv = init_vector.value();

        if (iv.size() < block_size) {
            iv.resize(block_size);
        }

        std::vector<std::byte> feedback = iv;

        for (size_t i = 0; i < new_data.size(); i += block_size) {
            std::vector<std::byte> block(
                    new_data.begin() + i,
                    new_data.begin() + std::min(i + block_size, new_data.size())
            );
            if (encrypt) {
                auto xor_block = xor_vectors(feedback, block, block_size);
                xor_block = this->algorithm->encrypt(xor_block);
                std::copy(xor_block.begin(), xor_block.end(), new_data.begin() + i);
                feedback = xor_vectors(block, xor_block, block_size);
            } else {
                auto encrypted_block = this->algorithm->decrypt(block);
                feedback = xor_vectors( feedback, encrypted_block, block_size);
                std::copy(feedback.begin(), feedback.end(), new_data.begin() + i);
                feedback = xor_vectors(block, feedback, block_size);
            }
        }

        return new_data;
    }

    std::vector<std::byte> CFB(const std::vector<std::byte>& data, bool encrypt) {
        if (!init_vector.has_value()) {
            throw std::runtime_error("Initialization vector is required for CBC mode");
        }
        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data = data;

        if (encrypt) {
            size_t required_blocks = (data.size() + block_size - 1) / block_size;
            padding(new_data, required_blocks * block_size);
        }

        auto& iv = init_vector.value();

        if (iv.size() < block_size) {
            iv.resize(block_size);
        }

        std::vector<std::byte> feedback = iv;

        for (size_t i = 0; i < new_data.size(); i += block_size) {
            auto encrypted_block = this->algorithm->encrypt(feedback);
            std::vector<std::byte> block(
                    new_data.begin() + i,
                    new_data.begin() + std::min(i + block_size, new_data.size())
            );
            if (encrypt) {
                feedback = xor_vectors(block, encrypted_block, block_size);
                std::copy(feedback.begin(), feedback.end(), new_data.begin() + i);
            } else {
                auto text = xor_vectors(encrypted_block, block, block_size);
                std::copy(text.begin(), text.end(), new_data.begin() + i);
                feedback = block;
            }
        }

        return new_data;
    }
    std::vector<std::byte> OFB(const std::vector<std::byte>& data, bool encrypt);
    std::vector<std::byte> CTR(const std::vector<std::byte>& data, bool encrypt);
    std::vector<std::byte> RandomDelta(const std::vector<std::byte>& data, bool encrypt);

    void padding(std::vector<std::byte>& data, size_t n_bytes) {
        size_t prev_size = data.size();
        data.resize(n_bytes);
        switch (this->padding_mode) {
            case PaddingModes::Zeros:
                break;
            case PaddingModes::ANSIX_923:
                data.at(data.size() - 1) = static_cast<std::byte>(n_bytes - prev_size);
                break;
            case PaddingModes::PKCS7:
                for (size_t i = prev_size; i < data.size(); ++i) {
                    data[i] = static_cast<std::byte>(n_bytes - prev_size);
                }
                break;
            case PaddingModes::ISO_10126:
                for (size_t i = prev_size; i < data.size() - 1; ++i) {
                    auto value = std::rand() % 256;
                    data[i] = static_cast<std::byte>(value);
                }
                data[data.size() - 1] = static_cast<std::byte>(n_bytes - prev_size);
        }
    }

};

int main() {


    return 0;
}