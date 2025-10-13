#include "symmetric_algorithm.hpp"

namespace symmerical_algorithm {

    std::vector<std::byte> TestEncyption::encrypt(const std::vector<std::byte>& block) {
        return block;
    }

    std::vector<std::byte> TestEncyption::decrypt(const std::vector<std::byte>& block) {
        return block;
    }

    size_t TestEncyption::get_block_size() {
        return 8;
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
        // Implementation for async encryption
        return std::async(std::launch::async, [this, data]() -> std::vector<std::byte> {
            std::lock_guard<std::mutex> lock(mutex);
            // Implementation here
            return data;
        });
    }

    std::future<void> SymmetricAlgorithm::encrypt(const std::filesystem::path& input_file,
                                                  const std::filesystem::path& output_file) {
        // Implementation for file encryption
        return std::async(std::launch::async, [this, input_file, output_file]() {
            // Implementation here
        });
    }

    std::future<std::vector<std::byte>> SymmetricAlgorithm::decrypt(const std::vector<std::byte>& data) {
        // Implementation for async decryption
        return std::async(std::launch::async, [this, data]() -> std::vector<std::byte> {
            std::lock_guard<std::mutex> lock(mutex);
            // Implementation here
            return data;
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

    std::vector<std::byte> SymmetricAlgorithm::CBC(const std::vector<std::byte>& data, bool encrypt) {
        if (!init_vector.has_value()) {
            throw std::runtime_error("Initialization vector is required for CBC mode");
        }

        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data = data;
        auto& iv = init_vector.value();

        if (iv.size() < block_size) {
            iv.resize(block_size);
        }

        if (encrypt) {
            size_t required_blocks = (data.size() + block_size - 1) / block_size;
            padding(new_data, required_blocks * block_size);

            std::vector<std::byte> previous_block = iv;

            for (size_t i = 0; i < new_data.size(); i += block_size) {
                std::vector<std::byte> block(
                        new_data.begin() + i,
                        new_data.begin() + std::min(i + block_size, new_data.size())
                );

                auto xored_block = bits_functions::xor_vectors(block, previous_block, block_size);
                auto processed_block = this->algorithm->encrypt(xored_block);

                std::copy(processed_block.begin(), processed_block.end(), new_data.begin() + i);
                previous_block = processed_block;
            }
        } else {

            std::vector<std::thread> threads;
            std::vector<std::byte> iv_copy = iv;

            for (size_t i = 0; i < new_data.size(); i += block_size) {
                threads.emplace_back([this, &new_data, iv_copy, i, block_size]() {
                    const size_t block_index = i / block_size;

                    std::vector<std::byte> block(
                            new_data.begin() + i,
                            new_data.begin() + std::min(i + block_size, new_data.size())
                    );

                    std::vector<std::byte> previous_block;
                    if (block_index == 0) {
                        previous_block = iv_copy;
                    } else {
                        previous_block = std::vector<std::byte>(
                                new_data.begin() + (i - block_size),
                                new_data.begin() + i
                        );
                    }

                    auto decrypted_block = this->algorithm->decrypt(block);
                    auto plain_block = bits_functions::xor_vectors(decrypted_block, previous_block, block_size);

                    std::copy(plain_block.begin(), plain_block.end(), new_data.begin() + i);
                });
            }

            for (auto& t : threads) {
                t.join();
            }
        }

        return new_data;
    }

    std::vector<std::byte> SymmetricAlgorithm::PCBC(const std::vector<std::byte>& data, bool encrypt) {
        if (!init_vector.has_value()) {
            throw std::runtime_error("Initialization vector is required for PCBC mode");
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
                auto xor_block = bits_functions::xor_vectors(feedback, block, block_size);
                xor_block = this->algorithm->encrypt(xor_block);
                std::copy(xor_block.begin(), xor_block.end(), new_data.begin() + i);
                feedback = bits_functions::xor_vectors(block, xor_block, block_size);
            } else {
                auto encrypted_block = this->algorithm->decrypt(block);
                feedback = bits_functions::xor_vectors( feedback, encrypted_block, block_size);
                std::copy(feedback.begin(), feedback.end(), new_data.begin() + i);
                feedback = bits_functions::xor_vectors(block, feedback, block_size);
            }
        }

        return new_data;
    }

    std::vector<std::byte> SymmetricAlgorithm::CFB(const std::vector<std::byte>& data, bool encrypt) {
        if (!init_vector.has_value()) {
            throw std::runtime_error("Initialization vector is required for CFB mode");
        }

        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data = data;


        auto& iv = init_vector.value();
        if (iv.size() < block_size) {
            iv.resize(block_size);
        }

        if (encrypt) {
            size_t required_blocks = (data.size() + block_size - 1) / block_size;
            padding(new_data, required_blocks * block_size);

            std::vector<std::byte> feedback = iv;

            for (size_t i = 0; i < new_data.size(); i += block_size) {
                auto encrypted_block = this->algorithm->encrypt(feedback);
                std::vector<std::byte> block(
                        new_data.begin() + i,
                        new_data.begin() + std::min(i + block_size, new_data.size())
                );

                feedback = bits_functions::xor_vectors(block, encrypted_block, block_size);
                std::copy(feedback.begin(), feedback.end(), new_data.begin() + i);
            }
        } else {

            std::vector<std::thread> threads;
            std::vector<std::byte> iv_copy = iv;

            for (size_t i = 0; i < new_data.size(); i += block_size) {
                threads.emplace_back([this, &new_data, iv_copy, i, block_size]() {
                    const size_t block_index = i / block_size;

                    std::vector<std::byte> block(
                            new_data.begin() + i,
                            new_data.begin() + std::min(i + block_size, new_data.size())
                    );

                    std::vector<std::byte> feedback;
                    if (block_index == 0) {
                        feedback = iv_copy;
                    } else {
                        feedback = std::vector<std::byte>(
                                new_data.begin() + (i - block_size),
                                new_data.begin() + i
                        );
                    }

                    auto encrypted_feedback = this->algorithm->encrypt(feedback);
                    auto plain_block = bits_functions::xor_vectors(encrypted_feedback, block, block_size);

                    std::copy(plain_block.begin(), plain_block.end(), new_data.begin() + i);
                });
            }

            for (auto& t : threads) {
                t.join();
            }
        }

        return new_data;
    }

    std::vector<std::byte> SymmetricAlgorithm::OFB(const std::vector<std::byte>& data, bool encrypt) {
        if (!init_vector.has_value()) {
            throw std::runtime_error("Initialization vector is required for OFB mode");
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
            feedback = this->algorithm->encrypt(feedback);
            std::vector<std::byte> block(
                    new_data.begin() + i,
                    new_data.begin() + std::min(i + block_size, new_data.size())
            );
            auto encrypted_block = bits_functions::xor_vectors(feedback, block, block_size);
            std::copy(encrypted_block.begin(), encrypted_block.end(), new_data.begin() + i);
        }

        return new_data;
    }

    std::vector<std::byte> SymmetricAlgorithm::CTR(const std::vector<std::byte>& data, bool encrypt) {
        if (!init_vector.has_value()) {
            throw std::runtime_error("Initialization vector is required for CTR mode");
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

        std::vector<std::thread> threads;

        std::atomic<uint64_t> counter(0);

        for (size_t i = 0; i < new_data.size(); i += block_size) {
            threads.emplace_back([this, &new_data, iv, &counter, block_size, i]() {
                std::vector<std::byte> block(
                        new_data.begin() + i,
                        new_data.begin() + std::min(i + block_size, new_data.size())
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
        std::vector<std::byte> new_data = data;

        if (encrypt) {
            size_t required_blocks = (data.size() + block_size - 1) / block_size;
            padding(new_data, required_blocks * block_size);
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
            threads.emplace_back([this, &new_data, &iv, block_size, i, random_delta]() {
                std::vector<std::byte> block(
                        new_data.begin() + i,
                        new_data.begin() + std::min(i + block_size, new_data.size())
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

        return new_data;
    }

    void SymmetricAlgorithm::padding(std::vector<std::byte>& data, size_t n_bytes) {
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
}