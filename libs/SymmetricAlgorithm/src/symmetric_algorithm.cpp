#include "symmetric_algorithm.hpp"

namespace symmerical_algorithm {

    std::vector<std::byte> TestEncryption::encrypt(const std::vector<std::byte>& block) {
        std::vector<std::byte> result(block.size());
        for (size_t i = 0; i < block.size(); ++i) {
            result[i] = block[i] ^ key[i % key.size()];
        }
        return result;
    }

    std::vector<std::byte> TestEncryption::decrypt(const std::vector<std::byte>& block) {
        return encrypt(block);
    }

    size_t TestEncryption::get_block_size() {
        return block_size;
    }

    void TestEncryption::set_key(const std::vector<std::byte>& key) {
        this->key = key;
    }

    SymmetricAlgorithm::SymmetricAlgorithm(std::vector<std::byte> key_,
                                           EncryptionModes encryption_mode_,
                                           PaddingModes padding_mode_,
                                           std::optional<std::vector<std::byte>> init_vector_,
                                           std::vector<std::any> params_,
                                           std::unique_ptr<SymmetricEncryption> algorithm_)
            : key(std::move(key_)),
              encryption_mode(encryption_mode_),
              padding_mode(padding_mode_),
              init_vector(std::move(init_vector_)),
              params(std::move(params_)),
              algorithm(std::move(algorithm_)) {}

    std::future<std::vector<std::byte>> SymmetricAlgorithm::encrypt(const std::vector<std::byte>& data) {
        return std::async(std::launch::async, [this, data]() -> std::vector<std::byte> {
            std::lock_guard<std::mutex> lock(mutex);
            switch (encryption_mode) {
                case EncryptionModes::ECB: return ECB(data, true);
                case EncryptionModes::CBC: return CBC(data, true);
                case EncryptionModes::PCBC: return PCBC(data, true);
                case EncryptionModes::CFB: return CFB(data, true);
                case EncryptionModes::OFB: return OFB(data, true);
                case EncryptionModes::CTR: return CTR(data, true);
                case EncryptionModes::RandomDelta: return RandomDelta(data, true);
                default: throw std::runtime_error("Invalid encryption mode");
            }
        });
    }

    std::future<void> SymmetricAlgorithm::encrypt(const std::filesystem::path& input_file,
                                                  const std::filesystem::path& output_file) {
        return std::async(std::launch::async, [this, input_file, output_file]() {
            std::lock_guard<std::mutex> lock(mutex);
        });
    }

    std::future<std::vector<std::byte>> SymmetricAlgorithm::decrypt(const std::vector<std::byte>& data) {
        return std::async(std::launch::async, [this, data]() -> std::vector<std::byte> {
            std::lock_guard<std::mutex> lock(mutex);
            switch (encryption_mode) {
                case EncryptionModes::ECB: return ECB(data, false);
                case EncryptionModes::CBC: return CBC(data, false);
                case EncryptionModes::PCBC: return PCBC(data, false);
                case EncryptionModes::CFB: return CFB(data, false);
                case EncryptionModes::OFB: return OFB(data, false);
                case EncryptionModes::CTR: return CTR(data, false);
                case EncryptionModes::RandomDelta: return RandomDelta(data, false);
                default: throw std::runtime_error("Invalid encryption mode");
            }
        });
    }

    std::future<void> SymmetricAlgorithm::decrypt(const std::filesystem::path& input_file,
                                                  const std::filesystem::path& output_file) {
        // Implementation for file decryption
        return std::async(std::launch::async, [this, input_file, output_file]() {
            // Implementation here
        });
    }

    std::vector<std::byte> SymmetricAlgorithm::ECB(const std::vector<std::byte>& data, bool encrypt) {
        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data;

        if (encrypt) {
            new_data = data;
            size_t required_size = ((data.size() + block_size - 1) / block_size) * block_size;
            padding(new_data, required_size);
        } else {
            new_data = data;
        }


        // remove threading temporarily
        for (size_t i = 0; i < new_data.size(); i += block_size) {
            size_t end_index = std::min(i + block_size, new_data.size());
            std::vector<std::byte> block(new_data.begin() + i, new_data.begin() + end_index);

            std::vector<std::byte> processed_block;
            if (encrypt) {
                processed_block = this->algorithm->encrypt(block);
            } else {
                processed_block = this->algorithm->decrypt(block);
            }

            std::copy(processed_block.begin(), processed_block.end(), new_data.begin() + i);
        }

        if (!encrypt) {
            remove_padding(new_data);
        }

        return new_data;
    }
    std::vector<std::byte> SymmetricAlgorithm::CBC(const std::vector<std::byte>& data, bool encrypt) {
        if (!init_vector.has_value()) {
            throw std::runtime_error("Initialization vector is required for CBC mode");
        }

        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data;
        auto& iv = init_vector.value();

        if (iv.size() < block_size) {
            iv.resize(block_size);
        }

        if (encrypt) {
            new_data = data;
            size_t required_size = ((data.size() + block_size - 1) / block_size) * block_size;
            padding(new_data, required_size);
        } else {
            new_data = data;
        }

        if (encrypt) {
            std::vector<std::byte> previous_block = iv;

            for (size_t i = 0; i < new_data.size(); i += block_size) {
                size_t end_index = std::min(i + block_size, new_data.size());
                std::vector<std::byte> block(new_data.begin() + i, new_data.begin() + end_index);

                auto xored_block = bits_functions::xor_vectors(block, previous_block, block.size());
                auto processed_block = this->algorithm->encrypt(xored_block);

                std::copy(processed_block.begin(), processed_block.end(), new_data.begin() + i);
                previous_block = processed_block;
            }
        } else {
            std::vector<std::byte> previous_block = iv;

            for (size_t i = 0; i < new_data.size(); i += block_size) {
                size_t end_index = std::min(i + block_size, new_data.size());
                std::vector<std::byte> block(new_data.begin() + i, new_data.begin() + end_index);

                auto decrypted_block = this->algorithm->decrypt(block);
                auto plain_block = bits_functions::xor_vectors(decrypted_block, previous_block, block.size());

                std::copy(plain_block.begin(), plain_block.end(), new_data.begin() + i);
                previous_block = block;
            }

            remove_padding(new_data);
        }

        return new_data;
    }

    std::vector<std::byte> SymmetricAlgorithm::PCBC(const std::vector<std::byte>& data, bool encrypt) {
        if (!init_vector.has_value()) {
            throw std::runtime_error("Initialization vector is required for PCBC mode");
        }

        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data;
        auto& iv = init_vector.value();

        if (iv.size() < block_size) {
            iv.resize(block_size);
        }

        if (encrypt) {
            new_data = data;
            size_t required_size = ((data.size() + block_size - 1) / block_size) * block_size;
            padding(new_data, required_size);
        } else {
            new_data = data;
        }

        std::vector<std::byte> feedback = iv;

        for (size_t i = 0; i < new_data.size(); i += block_size) {
            size_t end_index = std::min(i + block_size, new_data.size());
            std::vector<std::byte> block(new_data.begin() + i, new_data.begin() + end_index);

            if (encrypt) {
                auto xor_block = bits_functions::xor_vectors(feedback, block, block.size());
                auto encrypted_block = this->algorithm->encrypt(xor_block);
                std::copy(encrypted_block.begin(), encrypted_block.end(), new_data.begin() + i);
                feedback = bits_functions::xor_vectors(block, encrypted_block, block.size());
            } else {
                auto decrypted_block = this->algorithm->decrypt(block);
                auto plain_block = bits_functions::xor_vectors(decrypted_block, feedback, block.size());
                std::copy(plain_block.begin(), plain_block.end(), new_data.begin() + i);
                feedback = bits_functions::xor_vectors(block, plain_block, block.size());
            }
        }

        if (!encrypt) {
            remove_padding(new_data);
        }
        return new_data;
    }


    std::vector<std::byte> SymmetricAlgorithm::CFB(const std::vector<std::byte>& data, bool encrypt) {
        if (!init_vector.has_value()) {
            throw std::runtime_error("Initialization vector is required for CFB mode");
        }

        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data;
        auto& iv = init_vector.value();

        if (iv.size() < block_size) {
            iv.resize(block_size);
        }

        if (encrypt) {
            new_data = data;
            size_t required_size = ((data.size() + block_size - 1) / block_size) * block_size;
            padding(new_data, required_size);
        } else {
            new_data = data;
        }

        if (encrypt) {
            std::vector<std::byte> feedback = iv;

            for (size_t i = 0; i < new_data.size(); i += block_size) {
                size_t end_index = std::min(i + block_size, new_data.size());
                std::vector<std::byte> block(new_data.begin() + i, new_data.begin() + end_index);

                auto encrypted_feedback = this->algorithm->encrypt(feedback);
                auto cipher_block = bits_functions::xor_vectors(block, encrypted_feedback, block.size());

                std::copy(cipher_block.begin(), cipher_block.end(), new_data.begin() + i);
                feedback = cipher_block;
            }
        } else {
            std::vector<std::byte> feedback = iv;

            for (size_t i = 0; i < new_data.size(); i += block_size) {
                size_t end_index = std::min(i + block_size, new_data.size());
                std::vector<std::byte> block(new_data.begin() + i, new_data.begin() + end_index);

                auto encrypted_feedback = this->algorithm->encrypt(feedback);
                auto plain_block = bits_functions::xor_vectors(block, encrypted_feedback, block.size());

                std::copy(plain_block.begin(), plain_block.end(), new_data.begin() + i);
                feedback = block;
            }

            remove_padding(new_data);
        }

        return new_data;
    }

    std::vector<std::byte> SymmetricAlgorithm::OFB(const std::vector<std::byte>& data, bool encrypt) {
        if (!init_vector.has_value()) {
            throw std::runtime_error("Initialization vector is required for OFB mode");
        }
        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data;
        new_data.resize(data.size());

        auto& iv = init_vector.value();

        if (iv.size() < block_size) {
            iv.resize(block_size);
        }

        std::vector<std::byte> feedback = iv;
        for (size_t i = 0; i < new_data.size(); i += block_size) {
            feedback = this->algorithm->encrypt(feedback);
            size_t current_block_size = std::min(block_size, data.size() - i);
            std::vector<std::byte> block(
                    data.begin() + i,
                    data.begin() + i +  current_block_size);
            std::vector<std::byte> keystream_block(
                    feedback.begin(),
                    feedback.begin() + current_block_size
            );
            auto encrypted_block = bits_functions::xor_vectors(keystream_block,
                                                               block, current_block_size);
            std::copy(encrypted_block.begin(), encrypted_block.end(), new_data.begin() + i);
        }

        return new_data;
    }

    std::vector<std::byte> SymmetricAlgorithm::CTR(const std::vector<std::byte>& data, bool encrypt) {
        if (!init_vector.has_value()) {
            throw std::runtime_error("Initialization vector is required for CTR mode");
        }

        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data;
        new_data.resize(data.size());

        auto& iv = init_vector.value();
        if (iv.size() < block_size) {
            iv.resize(block_size);
        }

        std::vector<std::thread> threads;

        std::atomic<uint64_t> counter(0);

        for (size_t i = 0; i < new_data.size(); i += block_size) {
            threads.emplace_back([this, &data, &new_data, iv, &counter, block_size, i]() {
                std::vector<std::byte> block(
                        data.begin() + i,
                        data.begin() + std::min(i + block_size, data.size())
                );

                uint64_t current_counter = counter.fetch_add(1, std::memory_order_relaxed);

                auto counter_value = bits_functions::add_number_to_bytes(iv, current_counter);
                auto encrypted_counter = this->algorithm->encrypt(counter_value);
                auto processed_block = bits_functions::xor_vectors(encrypted_counter, block, block_size);

                std::copy(processed_block.begin(), processed_block.end(), new_data.begin() + i);
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        return new_data;
    }

    std::vector<std::byte> SymmetricAlgorithm::RandomDelta(const std::vector<std::byte>& data, bool encrypt) {
        if (!init_vector.has_value()) {
            throw std::runtime_error("Initialization vector is required for CTR mode");
        }

        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data;

        if (encrypt) {
            new_data = data;
            size_t required_size = ((data.size() + block_size - 1) / block_size) * block_size;
            padding(new_data, required_size);
        } else {
            new_data = data;
        }

        auto& iv = init_vector.value();
        if (iv.size() < block_size) {
            iv.assign(iv.begin(), iv.begin() + iv.size() / 2);
            iv.resize(block_size);
        }

        std::vector<std::byte> random_delta(iv.begin() + iv.size() / 2 + 1, iv.end());
        random_delta.resize(block_size);
        std::vector<std::thread> threads;


        for (size_t i = 0; i < new_data.size(); i += block_size) {
            threads.emplace_back([this, &data, &new_data, &iv, block_size, i, random_delta]() {
                std::vector<std::byte> block(
                        data.begin() + i,
                        data.begin() + std::min(i + block_size, data.size())
                );

                iv = bits_functions::add_byte_vectors(iv, random_delta);
                auto xor_block = bits_functions::xor_vectors(iv, block, block_size);
                auto processed_block = this->algorithm->encrypt(xor_block);

                std::copy(processed_block.begin(), processed_block.end(), new_data.begin() + i);
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        if (!encrypt)
            remove_padding(new_data);
        return new_data;
    }


    void SymmetricAlgorithm::padding(std::vector<std::byte>& data, size_t target_size) {
        if (data.size() >= target_size) return;

        size_t original_size = data.size();
        size_t padding_size = target_size - original_size;
        data.resize(target_size);

        switch (padding_mode) {
            case PaddingModes::Zeros:
                std::fill(data.begin() + original_size, data.end(), std::byte{0});
                break;
            case PaddingModes::ANSIX_923:
                std::fill(data.begin() + original_size, data.end() - 1, std::byte{0});
                data.back() = static_cast<std::byte>(padding_size);
                break;
            case PaddingModes::PKCS7:
                std::fill(data.begin() + original_size, data.end(),
                          static_cast<std::byte>(padding_size));
                break;
            case PaddingModes::ISO_10126:
                std::generate(data.begin() + original_size, data.end() - 1, []() {
                    return static_cast<std::byte>(std::rand() % 256);
                });
                data.back() = static_cast<std::byte>(padding_size);
                break;
        }
    }

    void SymmetricAlgorithm::remove_padding(std::vector<std::byte>& data) {
        if (data.empty()) return;

        switch (padding_mode) {
            case PaddingModes::PKCS7:
            case PaddingModes::ISO_10126: {
                size_t padding_size = static_cast<size_t>(data.back());
                if (padding_size > 0 && padding_size <= data.size()) {
                    // Проверяем, что все байты padding корректны (для PKCS7)
                    if (padding_mode == PaddingModes::PKCS7) {
                        bool valid = true;
                        for (size_t i = data.size() - padding_size; i < data.size(); ++i) {
                            if (static_cast<size_t>(data[i]) != padding_size) {
                                valid = false;
                                break;
                            }
                        }
                        if (valid) {
                            data.resize(data.size() - padding_size);
                        }
                    } else {
                        data.resize(data.size() - padding_size);
                    }
                }
                break;
            }
            case PaddingModes::ANSIX_923: {
                size_t padding_size = static_cast<size_t>(data.back());
                if (padding_size > 0 && padding_size <= data.size()) {
                    bool valid_padding = true;
                    for (size_t i = data.size() - padding_size; i < data.size() - 1; ++i) {
                        if (data[i] != std::byte{0}) {
                            valid_padding = false;
                            break;
                        }
                    }
                    if (valid_padding) {
                        data.resize(data.size() - padding_size);
                    }
                }
                break;
            }
            case PaddingModes::Zeros:
                // Для Zero padding нужно знать исходный размер данных
                // В общем случае это сложно, поэтому обычно не используется
                // или требуется внешняя информация о размере
                break;
        }
    }
}