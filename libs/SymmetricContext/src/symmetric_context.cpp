#include "symmetric_context.hpp"

namespace symmetric_context {

    SymmetricContext::SymmetricContext(std::vector<std::byte> key_,
                                       EncryptionModes encryption_mode_,
                                       PaddingModes padding_mode_,
                                       std::optional<std::vector<std::byte>> init_vector_,
                                       std::vector<std::any> params_,
                                       std::unique_ptr<SymmetricAlgorithm> algorithm_)
            : encryption_mode(std::move(key_), encryption_mode_, std::move(init_vector_), std::move(algorithm_)),
              padding_mode(padding_mode_),
              params(std::move(params_)) {}

    std::vector<std::byte> SymmetricContext::apply_padding(const std::vector<std::byte>& data) {
        auto block_size = encryption_mode.get_block_size();
        std::vector<std::byte> padded_data = data;
        size_t required_size = ((data.size() + block_size - 1) / block_size) * block_size;
        padding_mode.padding(padded_data, required_size);
        return padded_data;
    }

    std::vector<std::byte> SymmetricContext::remove_padding(const std::vector<std::byte>& data) {
        std::vector<std::byte> unpadded_data = data;
        padding_mode.remove_padding(unpadded_data);
        return unpadded_data;
    }

    std::future<std::vector<std::byte>> SymmetricContext::encrypt(const std::vector<std::byte>& data) {
        return std::async(std::launch::async, [this, data]() -> std::vector<std::byte> {
            std::lock_guard<std::mutex> lock(mutex);
            auto padded_data = apply_padding(data);

            std::vector<std::byte> encrypted_data;
            switch (encryption_mode.encryption_mode) {
                case EncryptionModes::ECB:
                    encrypted_data = encryption_mode.ECB_encrypt(padded_data);
                    break;
                case EncryptionModes::CBC:
                    encrypted_data = encryption_mode.CBC_encrypt(padded_data);
                    break;
                case EncryptionModes::PCBC:
                    encrypted_data = encryption_mode.PCBC_encrypt(padded_data);
                    break;
                case EncryptionModes::CFB:
                    encrypted_data = encryption_mode.CFB_encrypt(padded_data);
                    break;
                case EncryptionModes::OFB:
                    encrypted_data = encryption_mode.OFB_encrypt(padded_data);
                    break;
                case EncryptionModes::CTR:
                    encrypted_data = encryption_mode.CTR_encrypt(padded_data);
                    break;
                case EncryptionModes::RandomDelta:
                    encrypted_data = encryption_mode.RandomDelta_encrypt(padded_data);
                    break;
                default:
                    throw std::runtime_error("Invalid encryption mode");
            }
            return encrypted_data;
        });
    }

    std::future<void> SymmetricContext::encrypt(const std::filesystem::path& input_file,
                                                std::optional<std::filesystem::path>& output_file) {
        return std::async(std::launch::async, [this, input_file, output_file]() {
            std::lock_guard<std::mutex> lock(mutex);

            if (!std::filesystem::exists(input_file)) {
                throw std::runtime_error("Input file does not exist: " + input_file.string());
            }

            std::filesystem::path actual_output_path;
            if (output_file.has_value()) {
                actual_output_path = output_file.value();
            } else {
                actual_output_path = input_file.parent_path() /
                                     (input_file.stem().string() + "_encrypted" + input_file.extension().string());
            }

            auto output_dir = actual_output_path.parent_path();
            if (!output_dir.empty() && !std::filesystem::exists(output_dir)) {
                std::filesystem::create_directories(output_dir);
            }

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

            std::vector<std::byte> file_data(file_size);
            in_file.read(reinterpret_cast<char*>(file_data.data()), file_size);

            auto padded_data = apply_padding(file_data);
            std::vector<std::byte> encrypted_data;

            switch (encryption_mode.encryption_mode) {
                case EncryptionModes::ECB:
                    encrypted_data = encryption_mode.ECB_encrypt(padded_data);
                    break;
                case EncryptionModes::CBC:
                    encrypted_data = encryption_mode.CBC_encrypt(padded_data);
                    break;
                case EncryptionModes::PCBC:
                    encrypted_data = encryption_mode.PCBC_encrypt(padded_data);
                    break;
                case EncryptionModes::CFB:
                    encrypted_data = encryption_mode.CFB_encrypt(padded_data);
                    break;
                case EncryptionModes::OFB:
                    encrypted_data = encryption_mode.OFB_encrypt(padded_data);
                    break;
                case EncryptionModes::CTR:
                    encrypted_data = encryption_mode.CTR_encrypt(padded_data);
                    break;
                case EncryptionModes::RandomDelta:
                    encrypted_data = encryption_mode.RandomDelta_encrypt(padded_data);
                    break;
                default:
                    throw std::runtime_error("Unsupported encryption mode");
            }

            out_file.write(reinterpret_cast<const char*>(encrypted_data.data()), encrypted_data.size());

            in_file.close();
            out_file.close();

            std::cout << "File encrypted: " << input_file << " -> " << actual_output_path << std::endl;
        });
    }

    std::future<std::vector<std::byte>> SymmetricContext::decrypt(const std::vector<std::byte>& data) {
        return std::async(std::launch::async, [this, data]() -> std::vector<std::byte> {
            std::lock_guard<std::mutex> lock(mutex);
            std::vector<std::byte> decrypted_data;

            switch (encryption_mode.encryption_mode) {
                case EncryptionModes::ECB:
                    decrypted_data = encryption_mode.ECB_decrypt(data);
                    break;
                case EncryptionModes::CBC:
                    decrypted_data = encryption_mode.CBC_decrypt(data);
                    break;
                case EncryptionModes::PCBC:
                    decrypted_data = encryption_mode.PCBC_decrypt(data);
                    break;
                case EncryptionModes::CFB:
                    decrypted_data = encryption_mode.CFB_decrypt(data);
                    break;
                case EncryptionModes::OFB:
                    decrypted_data = encryption_mode.OFB_decrypt(data);
                    break;
                case EncryptionModes::CTR:
                    decrypted_data = encryption_mode.CTR_decrypt(data);
                    break;
                case EncryptionModes::RandomDelta:
                    decrypted_data = encryption_mode.RandomDelta_decrypt(data);
                    break;
                default:
                    throw std::runtime_error("Invalid encryption mode");
            }

            return remove_padding(decrypted_data);
        });
    }

    std::future<void> SymmetricContext::decrypt(const std::filesystem::path& input_file,
                                                std::optional<std::filesystem::path>& output_file) {
        return std::async(std::launch::async, [this, input_file, output_file]() {
            std::lock_guard<std::mutex> lock(mutex);
            if (!std::filesystem::exists(input_file)) {
                throw std::runtime_error("Input file does not exist: " + input_file.string());
            }

            std::filesystem::path actual_output_path;
            if (output_file.has_value()) {
                actual_output_path = output_file.value();
            } else {
                std::string stem = input_file.stem().string();

                if (stem.length() > 10 && stem.substr(stem.length() - 10) == "_encrypted") {
                    stem = stem.substr(0, stem.length() - 10);
                }

                actual_output_path = input_file.parent_path() /
                                     (stem + "_decrypted" + input_file.extension().string());
            }

            auto output_dir = actual_output_path.parent_path();
            if (!output_dir.empty() && !std::filesystem::exists(output_dir)) {
                std::filesystem::create_directories(output_dir);
            }

            std::ifstream in_file(input_file, std::ios::binary);
            std::ofstream out_file(actual_output_path, std::ios::binary);

            if (!in_file.is_open() || !out_file.is_open()) {
                throw std::runtime_error("Cannot open input or output file");
            }

            in_file.seekg(0, std::ios::end);
            size_t file_size = in_file.tellg();
            in_file.seekg(0, std::ios::beg);

            std::vector<std::byte> encrypted_data(file_size);
            in_file.read(reinterpret_cast<char*>(encrypted_data.data()), file_size);

            std::vector<std::byte> decrypted_data;
            switch (encryption_mode.encryption_mode) {
                case EncryptionModes::ECB:
                    decrypted_data = encryption_mode.ECB_decrypt(encrypted_data);
                    break;
                case EncryptionModes::CBC:
                    decrypted_data = encryption_mode.CBC_decrypt(encrypted_data);
                    break;
                case EncryptionModes::PCBC:
                    decrypted_data = encryption_mode.PCBC_decrypt(encrypted_data);
                    break;
                case EncryptionModes::CFB:
                    decrypted_data = encryption_mode.CFB_decrypt(encrypted_data);
                    break;
                case EncryptionModes::OFB:
                    decrypted_data = encryption_mode.OFB_decrypt(encrypted_data);
                    break;
                case EncryptionModes::CTR:
                    decrypted_data = encryption_mode.CTR_decrypt(encrypted_data);
                    break;
                case EncryptionModes::RandomDelta:
                    decrypted_data = encryption_mode.RandomDelta_decrypt(encrypted_data);
                    break;
                default:
                    throw std::runtime_error("Unsupported encryption mode");
            }

            auto unpadded_data = remove_padding(decrypted_data);
            out_file.write(reinterpret_cast<const char*>(unpadded_data.data()), unpadded_data.size());

            in_file.close();
            out_file.close();

            std::cout << "File decrypted: " << input_file << " -> " << actual_output_path << std::endl;
        });
    }

    void PaddingMode::padding(std::vector<std::byte> &data, size_t target_size) {
        if (data.size() >= target_size) return;

        size_t original_size = data.size();
        size_t padding_size = target_size - original_size;
        data.resize(target_size);

        switch (this->mode) {
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

    void PaddingMode::remove_padding(std::vector<std::byte> &data) {
        if (data.empty()) return;

        switch (this->mode) {
            case PaddingModes::PKCS7:
            case PaddingModes::ISO_10126: {
                size_t padding_size = static_cast<size_t>(data.back());
                if (padding_size > 0 && padding_size <= data.size()) {
                    if (this->mode == PaddingModes::PKCS7) {
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
                break;
        }
    }


    std::vector<std::byte> EncryptionMode::ECB_encrypt(const std::vector<std::byte> &data) {
        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data = data;

        std::vector<std::thread> threads;
        std::mutex result_mutex;

        for (size_t i = 0; i < new_data.size(); i += block_size) {
            threads.emplace_back([&, i, block_size]() {
                size_t end_index = std::min(i + block_size, new_data.size());
                std::vector<std::byte> block(new_data.begin() + i, new_data.begin() + end_index);

                std::vector<std::byte> processed_block;
                processed_block = this->algorithm->encrypt(block);
                std::lock_guard<std::mutex> lock(result_mutex);
                std::copy(processed_block.begin(), processed_block.end(), new_data.begin() + i);
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        return new_data;
    }

    std::vector<std::byte> EncryptionMode::ECB_decrypt(const std::vector<std::byte> &data) {
        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data = data;

        std::vector<std::thread> threads;
        std::mutex result_mutex;

        for (size_t i = 0; i < new_data.size(); i += block_size) {
            threads.emplace_back([&, i, block_size]() {
                size_t end_index = std::min(i + block_size, new_data.size());
                std::vector<std::byte> block(new_data.begin() + i, new_data.begin() + end_index);

                std::vector<std::byte> processed_block;
                processed_block = this->algorithm->decrypt(block);

                std::lock_guard<std::mutex> lock(result_mutex);
                std::copy(processed_block.begin(), processed_block.end(), new_data.begin() + i);
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        return new_data;
    }

    std::vector<std::byte> EncryptionMode::CBC_encrypt(const std::vector<std::byte> &data) {
        if (!init_vector.has_value()) {
            throw std::runtime_error("Initialization vector is required for CBC mode");
        }

        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data = data;
        auto iv_copy = init_vector.value();
        if (iv_copy.size() < block_size) {
            iv_copy.resize(block_size);
        }

        std::vector<std::byte> previous_block = iv_copy;
        for (size_t i = 0; i < new_data.size(); i += block_size) {
            size_t end_index = i + block_size;
            std::vector<std::byte> block(new_data.begin() + i, new_data.begin() + end_index);

            auto xored_block = bits_functions::xor_vectors(block, previous_block, block.size());
            auto encrypted_block = this->algorithm->encrypt(xored_block);

            std::copy(encrypted_block.begin(), encrypted_block.end(), new_data.begin() + i);
            previous_block = encrypted_block;
        }

        return new_data;
    }

    std::vector<std::byte> EncryptionMode::CBC_decrypt(const std::vector<std::byte> &data) {
        if (!init_vector.has_value()) {
            throw std::runtime_error("Initialization vector is required for CBC mode");
        }

        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data;
        auto iv_copy = init_vector.value();
        if (iv_copy.size() < block_size) {
            iv_copy.resize(block_size);
        }

        new_data.resize(data.size());

        std::vector<std::thread> threads;
        std::mutex result_mutex;

        std::vector<std::byte> iv_local = iv_copy;

        for (size_t i = 0; i < data.size(); i += block_size) {
            threads.emplace_back([this, &data, &new_data, iv_local, i, block_size, &result_mutex]() {
                size_t end_index = std::min(i + block_size, data.size());
                std::vector<std::byte> encrypted_block(data.begin() + i, data.begin() + end_index);

                std::vector<std::byte> previous_encrypted_block;
                if (i == 0) {
                    previous_encrypted_block = iv_local;
                } else {
                    previous_encrypted_block = std::vector<std::byte>(
                            data.begin() + (i - block_size),
                            data.begin() + i
                    );
                }

                auto decrypted_block = this->algorithm->decrypt(encrypted_block);

                auto plain_block = bits_functions::xor_vectors(
                        decrypted_block,
                        previous_encrypted_block,
                        std::min(block_size, decrypted_block.size())
                );

                std::lock_guard<std::mutex> lock(result_mutex);
                std::copy(plain_block.begin(), plain_block.end(), new_data.begin() + i);
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        return new_data;
    }

    std::vector<std::byte> EncryptionMode::PCBC_encrypt(const std::vector<std::byte> &data) {
        if (!init_vector.has_value()) {
            throw std::runtime_error("Initialization vector is required for PCBC mode");
        }

        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data = data;
        auto& iv = init_vector.value();

        if (iv.size() < block_size) {
            iv.resize(block_size);
        }

        std::vector<std::byte> feedback = iv;
        for (size_t i = 0; i < new_data.size(); i += block_size) {
            size_t end_index = std::min(i + block_size, new_data.size());
            std::vector<std::byte> block(new_data.begin() + i, new_data.begin() + end_index);
            auto xor_block = bits_functions::xor_vectors(feedback, block, block.size());
            auto encrypted_block = this->algorithm->encrypt(xor_block);
            std::copy(encrypted_block.begin(), encrypted_block.end(), new_data.begin() + i);
            feedback = bits_functions::xor_vectors(block, encrypted_block, block.size());
        }

        return new_data;
    }

    std::vector<std::byte> EncryptionMode::PCBC_decrypt(const std::vector<std::byte> &data) {
        if (!init_vector.has_value()) {
            throw std::runtime_error("Initialization vector is required for PCBC mode");
        }

        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data = data;
        auto& iv = init_vector.value();

        if (iv.size() < block_size) {
            iv.resize(block_size);
        }

        std::vector<std::byte> feedback = iv;

        for (size_t i = 0; i < new_data.size(); i += block_size) {
            size_t end_index = std::min(i + block_size, new_data.size());
            std::vector<std::byte> block(new_data.begin() + i, new_data.begin() + end_index);
            auto decrypted_block = this->algorithm->decrypt(block);
            auto plain_block = bits_functions::xor_vectors(decrypted_block, feedback, block.size());
            std::copy(plain_block.begin(), plain_block.end(), new_data.begin() + i);
            feedback = bits_functions::xor_vectors(block, plain_block, block.size());
        }

        return new_data;
    }

    std::vector<std::byte> EncryptionMode::CFB_encrypt(const std::vector<std::byte> &data) {
        if (!init_vector.has_value()) {
            throw std::runtime_error("Initialization vector is required for CFB mode");
        }

        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data = data;
        auto iv_copy = init_vector.value();

        if (iv_copy.size() < block_size) {
            iv_copy.resize(block_size);
        }

        std::vector<std::byte> feedback = iv_copy;
        for (size_t i = 0; i < new_data.size(); i += block_size) {
            size_t end_index = std::min(i + block_size, new_data.size());
            std::vector<std::byte> block(new_data.begin() + i, new_data.begin() + end_index);
            auto encrypted_feedback = this->algorithm->encrypt(feedback);
            auto cipher_block = bits_functions::xor_vectors(block, encrypted_feedback, block.size());
            std::copy(cipher_block.begin(), cipher_block.end(), new_data.begin() + i);
            feedback = cipher_block;
        }

        return new_data;
    }

    std::vector<std::byte> EncryptionMode::CFB_decrypt(const std::vector<std::byte> &data) {
        if (!init_vector.has_value()) {
            throw std::runtime_error("Initialization vector is required for CFB mode");
        }

        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data = data;
        auto iv_copy = init_vector.value();

        if (iv_copy.size() < block_size) {
            iv_copy.resize(block_size);
        }

        std::vector<std::thread> threads;
        std::mutex result_mutex;

        for (size_t i = 0; i < new_data.size(); i += block_size) {
            threads.emplace_back([&, i, block_size]() {
                size_t end_index = std::min(i + block_size, new_data.size());
                std::vector<std::byte> block(new_data.begin() + i, new_data.begin() + end_index);

                std::vector<std::byte> feedback;
                if (i == 0) {
                    feedback = iv_copy;
                } else {
                    feedback = std::vector<std::byte>(
                            new_data.begin() + (i - block_size),
                            new_data.begin() + i
                    );
                }

                auto encrypted_feedback = this->algorithm->encrypt(feedback);
                auto plain_block = bits_functions::xor_vectors(block, encrypted_feedback, block.size());

                std::lock_guard<std::mutex> lock(result_mutex);
                std::copy(plain_block.begin(), plain_block.end(), new_data.begin() + i);
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        return new_data;
    }

    std::vector<std::byte> EncryptionMode::OFB_encrypt(const std::vector<std::byte> &data) {
        if (!init_vector.has_value()) {
            throw std::runtime_error("Initialization vector is required for OFB mode");
        }

        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data = data;

        auto iv_copy = init_vector.value();

        if (iv_copy.size() < block_size) {
            iv_copy.resize(block_size);
        }

        std::vector<std::byte> keystream = iv_copy;
        for (size_t i = 0; i < new_data.size(); i += block_size) {
            keystream = this->algorithm->encrypt(keystream);
            size_t current_block_size = std::min(block_size, new_data.size() - i);
            std::vector<std::byte> block(new_data.begin() + i, new_data.begin() + i + current_block_size);
            std::vector<std::byte> keystream_block(keystream.begin(), keystream.begin() + current_block_size);
            auto processed_block = bits_functions::xor_vectors(block, keystream_block, current_block_size);
            std::copy(processed_block.begin(), processed_block.end(), new_data.begin() + i);
        }

        return new_data;
    }

    std::vector<std::byte> EncryptionMode::OFB_decrypt(const std::vector<std::byte> &data) {
        if (!init_vector.has_value()) {
            throw std::runtime_error("Initialization vector is required for OFB mode");
        }

        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data = data;
        auto iv_copy = init_vector.value();

        if (iv_copy.size() < block_size) {
            iv_copy.resize(block_size);
        }

        std::vector<std::thread> threads;
        std::mutex result_mutex;

        for (size_t i = 0; i < new_data.size(); i += block_size) {
            threads.emplace_back([&, i, block_size]() {
                size_t end_index = std::min(i + block_size, new_data.size());
                std::vector<std::byte> block(new_data.begin() + i, new_data.begin() + end_index);

                std::vector<std::byte> feedback;
                if (i == 0) {
                    feedback = iv_copy;
                } else {
                    feedback = std::vector<std::byte>(
                            new_data.begin() + (i - block_size),
                            new_data.begin() + i
                    );
                }

                auto encrypted_feedback = this->algorithm->encrypt(feedback);
                auto plain_block = bits_functions::xor_vectors(block, encrypted_feedback, block.size());

                std::lock_guard<std::mutex> lock(result_mutex);
                std::copy(plain_block.begin(), plain_block.end(), new_data.begin() + i);
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        return new_data;
    }

    std::vector<std::byte> EncryptionMode::CTR_encrypt(const std::vector<std::byte> &data) {
        if (!init_vector.has_value()) {
            throw std::runtime_error("Initialization vector is required for CTR mode");
        }

        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data = data;

        auto& iv = init_vector.value();
        if (iv.size() < block_size) {
            iv.resize(block_size);
        }

        std::vector<std::thread> threads;
        std::mutex result_mutex;
        std::atomic<uint64_t> counter(0);

        for (size_t i = 0; i < new_data.size(); i += block_size) {
            threads.emplace_back([&, i, block_size]() {
                size_t end_index = std::min(i + block_size, new_data.size());
                size_t current_block_size = end_index - i;
                std::vector<std::byte> block(new_data.begin() + i, new_data.begin() + end_index);

                uint64_t current_counter = counter.fetch_add(1, std::memory_order_relaxed);
                auto counter_value = bits_functions::add_number_to_bytes(iv, current_counter);
                auto encrypted_counter = this->algorithm->encrypt(counter_value);

                std::vector<std::byte> keystream_block(encrypted_counter.begin(), encrypted_counter.begin() + current_block_size);
                auto processed_block = bits_functions::xor_vectors(block, keystream_block, current_block_size);

                std::lock_guard<std::mutex> lock(result_mutex);
                std::copy(processed_block.begin(), processed_block.end(), new_data.begin() + i);
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        return new_data;
    }

    std::vector<std::byte> EncryptionMode::CTR_decrypt(const std::vector<std::byte> &data) {
        if (!init_vector.has_value()) {
            throw std::runtime_error("Initialization vector is required for CTR mode");
        }

        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data = data;

        auto& iv = init_vector.value();
        if (iv.size() < block_size) {
            iv.resize(block_size);
        }

        std::vector<std::thread> threads;
        std::mutex result_mutex;
        std::atomic<uint64_t> counter(0);

        for (size_t i = 0; i < new_data.size(); i += block_size) {
            threads.emplace_back([&, i, block_size]() {
                size_t end_index = std::min(i + block_size, new_data.size());
                size_t current_block_size = end_index - i;
                std::vector<std::byte> block(new_data.begin() + i, new_data.begin() + end_index);

                uint64_t current_counter = counter.fetch_add(1, std::memory_order_relaxed);
                auto counter_value = bits_functions::add_number_to_bytes(iv, current_counter);
                auto encrypted_counter = this->algorithm->encrypt(counter_value);

                std::vector<std::byte> keystream_block(encrypted_counter.begin(), encrypted_counter.begin() + current_block_size);
                auto processed_block = bits_functions::xor_vectors(block, keystream_block, current_block_size);

                std::lock_guard<std::mutex> lock(result_mutex);
                std::copy(processed_block.begin(), processed_block.end(), new_data.begin() + i);
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        return new_data;
    }

    std::vector<std::byte> EncryptionMode::RandomDelta_encrypt(const std::vector<std::byte> &data) {
        if (!init_vector.has_value()) {
            throw std::runtime_error("Initialization vector is required for RandomDelta mode");
        }

        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data = data;

        auto iv_copy = init_vector.value();
        if (iv_copy.size() < block_size) {
            iv_copy.resize(block_size);
        }

        std::vector<std::byte> random_delta(iv_copy.begin() + iv_copy.size() / 2, iv_copy.end());

        std::vector<std::byte> current_iv = iv_copy;
        std::vector<std::thread> threads;
        std::mutex result_mutex;
        for (size_t i = 0; i < new_data.size(); i += block_size) {
            threads.emplace_back([&, i, block_size] {
                current_iv = bits_functions::add_byte_vectors(current_iv, random_delta);
                size_t end_index = std::min(i + block_size, new_data.size());
                std::vector<std::byte> block(new_data.begin() + i, new_data.begin() + end_index);
                std::vector<std::byte> xor_block = bits_functions::xor_vectors(current_iv, block, block.size());
                std::vector<std::byte> processed_block = this->algorithm->encrypt(xor_block);
                std::lock_guard<std::mutex> lock(result_mutex);
                std::copy(processed_block.begin(), processed_block.end(), new_data.begin() + i);
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        return new_data;
    }

    std::vector<std::byte> EncryptionMode::RandomDelta_decrypt(const std::vector<std::byte> &data) {
        if (!init_vector.has_value()) {
            throw std::runtime_error("Initialization vector is required for RandomDelta mode");
        }

        auto block_size = this->algorithm->get_block_size();
        std::vector<std::byte> new_data = data;

        auto iv_copy = init_vector.value();
        if (iv_copy.size() < block_size) {
            iv_copy.resize(block_size);
        }

        std::vector<std::byte> random_delta(iv_copy.begin() + iv_copy.size() / 2, iv_copy.end());

        std::vector<std::byte> current_iv = iv_copy;
        std::vector<std::thread> threads;
        std::mutex result_mutex;
        for (size_t i = 0; i < new_data.size(); i += block_size) {
            threads.emplace_back([&, i, block_size] {
                current_iv = bits_functions::add_byte_vectors(current_iv, random_delta);
                size_t end_index = std::min(i + block_size, new_data.size());
                std::vector<std::byte> block(new_data.begin() + i, new_data.begin() + end_index);

                std::vector<std::byte> processed_block = this->algorithm->decrypt(block);
                std::vector<std::byte> xor_block = bits_functions::xor_vectors(current_iv, processed_block, block.size());
                std::lock_guard<std::mutex> lock(result_mutex);
                std::copy(xor_block.begin(), xor_block.end(), new_data.begin() + i);
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        return new_data;
    }

}