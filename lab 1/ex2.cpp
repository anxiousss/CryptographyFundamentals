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

#include "utility.hpp"

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
        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data = data;

        if (encrypt) {
            padding(new_data, data.size() / block_size);
        }

        if (this->init_vector.value().size() < block_size) {
            this->init_vector.value().resize(block_size);
        }

        std::vector<std::byte> block = std::vector<std::byte>(new_data.begin(), new_data.begin() + block_size);
        if (encrypt) {
            std::vector<std::byte> processed_block = xor_vectors(this->init_vector.value(), block, block_size);
            processed_block = this->algorithm->encrypt(processed_block);
            std::copy(processed_block.begin(), processed_block.end(), new_data.begin());
            for (size_t i = block_size; i < new_data.size(); i += block_size) {
                block.assign(new_data.begin() + i, new_data.begin() + std::min(i + block_size, new_data.size()));
                processed_block = xor_vectors(block, processed_block, block_size);
                processed_block = this->algorithm->encrypt(processed_block);
                std::copy(processed_block.begin(), processed_block.end(), new_data.begin() + i);

            }
        } else {
            std::vector<std::byte> processed_block = this->algorithm->decrypt(block);
            processed_block = xor_vectors(processed_block, this->init_vector.value(), block_size);
            std::copy(processed_block.begin(), processed_block.end(), new_data.begin());
            auto prev_block = block;
            for (size_t i = block_size;  i < new_data.size(); i += block_size) {
                block.assign(new_data.begin() + i, new_data.begin() + std::min(i + block_size, new_data.size()));
                processed_block = this->algorithm->decrypt(block);
                processed_block = xor_vectors(processed_block, prev_block, block_size);
                std::copy(processed_block.begin(), processed_block.end(), new_data.begin() + i);
                prev_block = block;
            }
        }

        return new_data;
    }
    std::vector<std::byte> PCBC(const std::vector<std::byte>& data, bool encrypt);
    std::vector<std::byte> CFB(const std::vector<std::byte>& data, bool encrypt);
    std::vector<std::byte> OFB(const std::vector<std::byte>& data, bool encrypt);
    std::vector<std::byte> CTR(const std::vector<std::byte>& data, bool encrypt);
    std::vector<std::byte> RandomDelta(const std::vector<std::byte>& data, bool encrypt);

    void padding(std::vector<std::byte>& data, size_t n_bytes) {
        size_t prev_size = data.size();
        data.resize(n_bytes);
        switch (this->padding_mode) {
            case PaddingModes::Zeros:
                for (int i = prev_size; i < data.size(); ++i) {
                    data[i] = static_cast<std::byte>(0);
                }
                break;
            case PaddingModes::ANSIX_923:
                data.at(data.size() - 1) = static_cast<std::byte>(n_bytes - prev_size);
                break;
            case PaddingModes::PKCS7:
                for (int i = prev_size; i < data.size(); ++i) {
                    data[i] = static_cast<std::byte>(n_bytes - prev_size);
                }
                break;
            case PaddingModes::ISO_10126:
                for (int i = prev_size; i < data.size() - 1; ++i) {
                    auto value = std::rand() % 256;
                    data[i] = static_cast<std::byte>(value);
                }
                data[data.size() - 1] = static_cast<std::byte>(n_bytes - prev_size);
        }
    }

};

int main() {
    TestEncyption test{};
    SymmetricAlgorithm s{{}, EncryptionModes::ECB, PaddingModes::Zeros,
                         std::nullopt, {}, std::make_unique<TestEncyption>(test)};
    std::vector<std::byte> msg(2);
    msg[0] = std::byte{10};
    msg[1] = std::byte{8};
    auto new_msg = s.ECB(msg, 1);
    for (auto m: new_msg) {
        std::cout << m << std::endl;
    }
}