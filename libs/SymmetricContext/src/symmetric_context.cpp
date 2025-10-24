#include "symmetric_context.hpp"

namespace symmetric_context {

    void ZerosPadding::padding(std::vector<std::byte>& data, size_t target_size) {
        if (data.size() >= target_size) return;
        size_t original_size = data.size();
        data.resize(target_size);
        std::fill(data.begin() + original_size, data.end(), std::byte{0});
    }

    void ZerosPadding::remove_padding(std::vector<std::byte>& data) {
    }

    void ANSIX923Padding::padding(std::vector<std::byte>& data, size_t target_size) {
        if (data.size() >= target_size) return;
        size_t original_size = data.size();
        size_t padding_size = target_size - original_size;
        data.resize(target_size);
        std::fill(data.begin() + original_size, data.end() - 1, std::byte{0});
        data.back() = static_cast<std::byte>(padding_size);
    }

    void ANSIX923Padding::remove_padding(std::vector<std::byte>& data) {
        if (data.empty()) return;
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
    }

    void PKCS7Padding::padding(std::vector<std::byte>& data, size_t target_size) {
        if (data.size() >= target_size) return;
        size_t original_size = data.size();
        size_t padding_size = target_size - original_size;
        data.resize(target_size);
        std::fill(data.begin() + original_size, data.end(), static_cast<std::byte>(padding_size));
    }

    void PKCS7Padding::remove_padding(std::vector<std::byte>& data) {
        if (data.empty()) return;
        size_t padding_size = static_cast<size_t>(data.back());
        if (padding_size > 0 && padding_size <= data.size()) {
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
        }
    }

    void ISO10126Padding::padding(std::vector<std::byte>& data, size_t target_size) {
        if (data.size() >= target_size) return;
        size_t original_size = data.size();
        size_t padding_size = target_size - original_size;
        data.resize(target_size);

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);

        for (size_t i = original_size; i < data.size() - 1; ++i) {
            data[i] = static_cast<std::byte>(dis(gen));
        }
        data.back() = static_cast<std::byte>(padding_size);
    }

    void ISO10126Padding::remove_padding(std::vector<std::byte>& data) {
        if (data.empty()) return;
        size_t padding_size = static_cast<size_t>(data.back());
        if (padding_size > 0 && padding_size <= data.size()) {
            data.resize(data.size() - padding_size);
        }
    }

    SymmetricContext::SymmetricContext(std::vector<std::byte> key_,
                                       EncryptionModes encryption_mode_,
                                       PaddingModes padding_mode_,
                                       std::optional<std::vector<std::byte>> init_vector_,
                                       std::vector<std::any> params_,
                                       std::unique_ptr<SymmetricAlgorithm> algorithm_)
            : params(std::move(params_)) {

        switch (padding_mode_) {
            case PaddingModes::Zeros:
                padding_mode = std::make_unique<ZerosPadding>();
                break;
            case PaddingModes::ANSIX_923:
                padding_mode = std::make_unique<ANSIX923Padding>();
                break;
            case PaddingModes::PKCS7:
                padding_mode = std::make_unique<PKCS7Padding>();
                break;
            case PaddingModes::ISO_10126:
                padding_mode = std::make_unique<ISO10126Padding>();
                break;
        }

        switch (encryption_mode_) {
            case EncryptionModes::ECB:
                encryption_mode = std::make_unique<ECBEncryption>(
                        std::move(key_), std::move(init_vector_), std::move(algorithm_));
                break;
            case EncryptionModes::CBC:
                encryption_mode = std::make_unique<CBCEncryption>(
                        std::move(key_), std::move(init_vector_), std::move(algorithm_));
                break;
            case EncryptionModes::PCBC:
                encryption_mode = std::make_unique<PCBCEncryption>(
                        std::move(key_), std::move(init_vector_), std::move(algorithm_));
                break;
            case EncryptionModes::CFB:
                encryption_mode = std::make_unique<CFBEncryption>(
                        std::move(key_), std::move(init_vector_), std::move(algorithm_));
                break;
            case EncryptionModes::OFB:
                encryption_mode = std::make_unique<OFBEncryption>(
                        std::move(key_), std::move(init_vector_), std::move(algorithm_));
                break;
            case EncryptionModes::CTR:
                encryption_mode = std::make_unique<CTREncryption>(
                        std::move(key_), std::move(init_vector_), std::move(algorithm_));
                break;
            case EncryptionModes::RandomDelta:
                encryption_mode = std::make_unique<RandomDeltaEncryption>(
                        std::move(key_), std::move(init_vector_), std::move(algorithm_));
                break;
        }
    }

    std::vector<std::byte> SymmetricContext::apply_padding(const std::vector<std::byte>& data) {
        auto block_size = encryption_mode->get_block_size();
        std::vector<std::byte> padded_data = data;
        size_t required_size = ((data.size() + block_size - 1) / block_size) * block_size;
        padding_mode->padding(padded_data, required_size);
        return padded_data;
    }

    std::vector<std::byte> SymmetricContext::remove_padding(const std::vector<std::byte>& data) {
        std::vector<std::byte> unpadded_data = data;
        padding_mode->remove_padding(unpadded_data);
        return unpadded_data;
    }

    std::future<std::vector<std::byte>> SymmetricContext::encrypt(const std::vector<std::byte>& data) {
        return std::async(std::launch::async, [this, data]() -> std::vector<std::byte> {
            std::lock_guard<std::mutex> lock(mutex);
            auto padded_data = apply_padding(data);
            return encryption_mode->encrypt(padded_data);
        });
    }

    std::future<void> SymmetricContext::encrypt(const std::filesystem::path& input_file,
                                                std::optional<std::filesystem::path>& output_file) {
        return std::async(std::launch::async, [this, input_file, output_file]() {
            std::lock_guard<std::mutex> lock(mutex);

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

            std::vector<std::byte> file_data(file_size);
            in_file.read(reinterpret_cast<char*>(file_data.data()), file_size);

            auto padded_data = apply_padding(file_data);
            auto encrypted_data = encryption_mode->encrypt(padded_data);

            out_file.write(reinterpret_cast<const char*>(encrypted_data.data()), encrypted_data.size());
            std::cout << "File encrypted: " << input_file << " -> " << actual_output_path << std::endl;
        });
    }

    std::future<std::vector<std::byte>> SymmetricContext::decrypt(const std::vector<std::byte>& data) {
        return std::async(std::launch::async, [this, data]() -> std::vector<std::byte> {
            std::lock_guard<std::mutex> lock(mutex);
            auto decrypted_data = encryption_mode->decrypt(data);
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

            std::vector<std::byte> encrypted_data(file_size);
            in_file.read(reinterpret_cast<char*>(encrypted_data.data()), file_size);

            auto decrypted_data = encryption_mode->decrypt(encrypted_data);
            auto unpadded_data = remove_padding(decrypted_data);
            out_file.write(reinterpret_cast<const char*>(unpadded_data.data()), unpadded_data.size());

            std::cout << "File decrypted: " << input_file << " -> " << actual_output_path << std::endl;
        });
    }


    std::vector<std::byte> ECBEncryption::encrypt(const std::vector<std::byte>& data) {
        auto block_size = algorithm->get_block_size();
        std::vector<std::byte> result = data;

        std::vector<std::thread> threads;
        std::mutex result_mutex;

        for (size_t i = 0; i < result.size(); i += block_size) {
            threads.emplace_back([&, i, block_size]() {
                size_t end_index = std::min(i + block_size, result.size());
                std::vector<std::byte> block(result.begin() + i, result.begin() + end_index);
                auto processed_block = algorithm->encrypt(block);

                std::lock_guard<std::mutex> lock(result_mutex);
                std::copy(processed_block.begin(), processed_block.end(), result.begin() + i);
            });
        }

        for (auto& t : threads) t.join();
        return result;
    }

    std::vector<std::byte> ECBEncryption::decrypt(const std::vector<std::byte>& data) {
        auto block_size = algorithm->get_block_size();
        std::vector<std::byte> result = data;

        std::vector<std::thread> threads;
        std::mutex result_mutex;

        for (size_t i = 0; i < result.size(); i += block_size) {
            threads.emplace_back([&, i, block_size]() {
                size_t end_index = std::min(i + block_size, result.size());
                std::vector<std::byte> block(result.begin() + i, result.begin() + end_index);
                auto processed_block = algorithm->decrypt(block);

                std::lock_guard<std::mutex> lock(result_mutex);
                std::copy(processed_block.begin(), processed_block.end(), result.begin() + i);
            });
        }

        for (auto& t : threads) t.join();
        return result;
    }

    std::vector<std::byte> CBCEncryption::encrypt(const std::vector<std::byte>& data) {
        if (!init_vector) {
            throw std::runtime_error("Initialization vector is required for CBC mode");
        }

        auto block_size = algorithm->get_block_size();
        std::vector<std::byte> result = data;
        auto iv = init_vector.value();
        if (iv.size() < block_size) iv.resize(block_size);

        std::vector<std::byte> previous_block = iv;
        for (size_t i = 0; i < result.size(); i += block_size) {
            size_t end_index = i + block_size;
            std::vector<std::byte> block(result.begin() + i, result.begin() + end_index);
            auto xored_block = bits_functions::xor_vectors(block, previous_block, block.size());
            auto encrypted_block = algorithm->encrypt(xored_block);
            std::copy(encrypted_block.begin(), encrypted_block.end(), result.begin() + i);
            previous_block = encrypted_block;
        }
        return result;
    }

    std::vector<std::byte> CBCEncryption::decrypt(const std::vector<std::byte>& data) {
        if (!init_vector) {
            throw std::runtime_error("Initialization vector is required for CBC mode");
        }

        auto block_size = algorithm->get_block_size();
        std::vector<std::byte> result(data.size());
        auto iv = init_vector.value();
        if (iv.size() < block_size) iv.resize(block_size);

        std::vector<std::thread> threads;
        std::mutex result_mutex;

        for (size_t i = 0; i < data.size(); i += block_size) {
            threads.emplace_back([&, i, block_size]() {
                size_t end_index = std::min(i + block_size, data.size());
                std::vector<std::byte> encrypted_block(data.begin() + i, data.begin() + end_index);

                std::vector<std::byte> previous_block;
                if (i == 0) previous_block = iv;
                else previous_block = std::vector<std::byte>(data.begin() + (i - block_size), data.begin() + i);

                auto decrypted_block = algorithm->decrypt(encrypted_block);
                auto plain_block = bits_functions::xor_vectors(decrypted_block, previous_block, block_size);

                std::lock_guard<std::mutex> lock(result_mutex);
                std::copy(plain_block.begin(), plain_block.end(), result.begin() + i);
            });
        }

        for (auto& t : threads) t.join();
        return result;
    }

    std::vector<std::byte> PCBCEncryption::encrypt(const std::vector<std::byte>& data) {
        if (!init_vector) throw std::runtime_error("IV required for PCBC mode");
        auto block_size = algorithm->get_block_size();
        std::vector<std::byte> result = data;
        auto iv = init_vector.value();
        if (iv.size() < block_size) iv.resize(block_size);

        std::vector<std::byte> feedback = iv;
        for (size_t i = 0; i < result.size(); i += block_size) {
            size_t end_index = std::min(i + block_size, result.size());
            std::vector<std::byte> block(result.begin() + i, result.begin() + end_index);
            auto xor_block = bits_functions::xor_vectors(feedback, block, block.size());
            auto encrypted_block = algorithm->encrypt(xor_block);
            std::copy(encrypted_block.begin(), encrypted_block.end(), result.begin() + i);
            feedback = bits_functions::xor_vectors(block, encrypted_block, block.size());
        }
        return result;
    }

    std::vector<std::byte> PCBCEncryption::decrypt(const std::vector<std::byte>& data) {
        if (!init_vector) throw std::runtime_error("IV required for PCBC mode");
        auto block_size = algorithm->get_block_size();
        std::vector<std::byte> result = data;
        auto iv = init_vector.value();
        if (iv.size() < block_size) iv.resize(block_size);

        std::vector<std::byte> feedback = iv;
        for (size_t i = 0; i < result.size(); i += block_size) {
            size_t end_index = std::min(i + block_size, result.size());
            std::vector<std::byte> block(result.begin() + i, result.begin() + end_index);
            auto decrypted_block = algorithm->decrypt(block);
            auto plain_block = bits_functions::xor_vectors(decrypted_block, feedback, block.size());
            std::copy(plain_block.begin(), plain_block.end(), result.begin() + i);
            feedback = bits_functions::xor_vectors(block, plain_block, block.size());
        }
        return result;
    }

    std::vector<std::byte> CFBEncryption::encrypt(const std::vector<std::byte>& data) {
        if (!init_vector) throw std::runtime_error("IV required for CFB mode");
        auto block_size = algorithm->get_block_size();
        std::vector<std::byte> result = data;
        auto iv = init_vector.value();
        if (iv.size() < block_size) iv.resize(block_size);

        std::vector<std::byte> feedback = iv;
        for (size_t i = 0; i < result.size(); i += block_size) {
            size_t end_index = std::min(i + block_size, result.size());
            std::vector<std::byte> block(result.begin() + i, result.begin() + end_index);
            auto encrypted_feedback = algorithm->encrypt(feedback);
            auto cipher_block = bits_functions::xor_vectors(block, encrypted_feedback, block.size());
            std::copy(cipher_block.begin(), cipher_block.end(), result.begin() + i);
            feedback = cipher_block;
        }
        return result;
    }

    std::vector<std::byte> CFBEncryption::decrypt(const std::vector<std::byte>& data) {
        if (!init_vector) throw std::runtime_error("IV required for CFB mode");
        auto block_size = algorithm->get_block_size();
        std::vector<std::byte> result = data;
        auto iv = init_vector.value();
        if (iv.size() < block_size) iv.resize(block_size);

        std::vector<std::thread> threads;
        std::mutex result_mutex;

        for (size_t i = 0; i < result.size(); i += block_size) {
            threads.emplace_back([&, i, block_size]() {
                size_t end_index = std::min(i + block_size, result.size());
                std::vector<std::byte> block(result.begin() + i, result.begin() + end_index);

                std::vector<std::byte> feedback;
                if (i == 0) feedback = iv;
                else feedback = std::vector<std::byte>(result.begin() + (i - block_size), result.begin() + i);

                auto encrypted_feedback = algorithm->encrypt(feedback);
                auto plain_block = bits_functions::xor_vectors(block, encrypted_feedback, block.size());

                std::lock_guard<std::mutex> lock(result_mutex);
                std::copy(plain_block.begin(), plain_block.end(), result.begin() + i);
            });
        }

        for (auto& t : threads) t.join();
        return result;
    }

    std::vector<std::byte> OFBEncryption::encrypt(const std::vector<std::byte>& data) {
        if (!init_vector) throw std::runtime_error("IV required for OFB mode");
        auto block_size = algorithm->get_block_size();
        std::vector<std::byte> result = data;
        auto iv = init_vector.value();
        if (iv.size() < block_size) iv.resize(block_size);

        std::vector<std::byte> keystream = iv;
        for (size_t i = 0; i < result.size(); i += block_size) {
            keystream = algorithm->encrypt(keystream);
            size_t current_block_size = std::min(block_size, result.size() - i);
            std::vector<std::byte> block(result.begin() + i, result.begin() + i + current_block_size);
            std::vector<std::byte> keystream_block(keystream.begin(), keystream.begin() + current_block_size);
            auto processed_block = bits_functions::xor_vectors(block, keystream_block, current_block_size);
            std::copy(processed_block.begin(), processed_block.end(), result.begin() + i);
        }
        return result;
    }

    std::vector<std::byte> OFBEncryption::decrypt(const std::vector<std::byte>& data) {
        if (!init_vector) throw std::runtime_error("IV required for OFB mode");
        auto block_size = algorithm->get_block_size();
        std::vector<std::byte> result = data;
        auto iv = init_vector.value();
        if (iv.size() < block_size) iv.resize(block_size);

        std::vector<std::byte> keystream = iv;
        for (size_t i = 0; i < result.size(); i += block_size) {
            keystream = algorithm->encrypt(keystream);
            size_t current_block_size = std::min(block_size, result.size() - i);
            std::vector<std::byte> block(result.begin() + i, result.begin() + i + current_block_size);
            std::vector<std::byte> keystream_block(keystream.begin(), keystream.begin() + current_block_size);
            auto processed_block = bits_functions::xor_vectors(block, keystream_block, current_block_size);
            std::copy(processed_block.begin(), processed_block.end(), result.begin() + i);
        }
        return result;
    }

    std::vector<std::byte> CTREncryption::encrypt(const std::vector<std::byte>& data) {
        if (!init_vector) throw std::runtime_error("IV required for CTR mode");
        auto block_size = algorithm->get_block_size();
        std::vector<std::byte> result = data;
        auto iv = init_vector.value();
        if (iv.size() < block_size) iv.resize(block_size);

        std::vector<std::thread> threads;
        std::mutex result_mutex;
        std::atomic<uint64_t> counter(0);

        for (size_t i = 0; i < result.size(); i += block_size) {
            threads.emplace_back([&, i, block_size]() {
                size_t end_index = std::min(i + block_size, result.size());
                size_t current_block_size = end_index - i;
                std::vector<std::byte> block(result.begin() + i, result.begin() + end_index);

                uint64_t current_counter = counter.fetch_add(1, std::memory_order_relaxed);
                auto counter_value = bits_functions::add_number_to_bytes(iv, current_counter);
                auto encrypted_counter = algorithm->encrypt(counter_value);

                std::vector<std::byte> keystream_block(encrypted_counter.begin(), encrypted_counter.begin() + current_block_size);
                auto processed_block = bits_functions::xor_vectors(block, keystream_block, current_block_size);

                std::lock_guard<std::mutex> lock(result_mutex);
                std::copy(processed_block.begin(), processed_block.end(), result.begin() + i);
            });
        }

        for (auto& t : threads) t.join();
        return result;
    }

    std::vector<std::byte> CTREncryption::decrypt(const std::vector<std::byte>& data) {
        if (!init_vector) throw std::runtime_error("IV required for CTR mode");
        auto block_size = algorithm->get_block_size();
        std::vector<std::byte> result = data;
        auto iv = init_vector.value();
        if (iv.size() < block_size) iv.resize(block_size);

        std::vector<std::thread> threads;
        std::mutex result_mutex;
        std::atomic<uint64_t> counter(0);

        for (size_t i = 0; i < result.size(); i += block_size) {
            threads.emplace_back([&, i, block_size]() {
                size_t end_index = std::min(i + block_size, result.size());
                size_t current_block_size = end_index - i;
                std::vector<std::byte> block(result.begin() + i, result.begin() + end_index);

                uint64_t current_counter = counter.fetch_add(1, std::memory_order_relaxed);
                auto counter_value = bits_functions::add_number_to_bytes(iv, current_counter);
                auto encrypted_counter = algorithm->encrypt(counter_value);

                std::vector<std::byte> keystream_block(encrypted_counter.begin(), encrypted_counter.begin() + current_block_size);
                auto processed_block = bits_functions::xor_vectors(block, keystream_block, current_block_size);

                std::lock_guard<std::mutex> lock(result_mutex);
                std::copy(processed_block.begin(), processed_block.end(), result.begin() + i);
            });
        }

        for (auto& t : threads) t.join();
        return result;
    }

    std::vector<std::byte> RandomDeltaEncryption::encrypt(const std::vector<std::byte>& data) {
        if (!init_vector) throw std::runtime_error("IV required for RandomDelta mode");
        auto block_size = algorithm->get_block_size();
        std::vector<std::byte> result = data;
        auto iv = init_vector.value();
        if (iv.size() < block_size) iv.resize(block_size);

        std::vector<std::byte> random_delta(iv.begin() + iv.size() / 2, iv.end());
        std::vector<std::byte> current_iv = iv;

        std::vector<std::thread> threads;
        std::mutex result_mutex;

        for (size_t i = 0; i < result.size(); i += block_size) {
            threads.emplace_back([&, i, block_size]() {
                current_iv = bits_functions::add_byte_vectors(current_iv, random_delta);
                size_t end_index = std::min(i + block_size, result.size());
                std::vector<std::byte> block(result.begin() + i, result.begin() + end_index);
                std::vector<std::byte> xor_block = bits_functions::xor_vectors(current_iv, block, block.size());
                std::vector<std::byte> processed_block = algorithm->encrypt(xor_block);

                std::lock_guard<std::mutex> lock(result_mutex);
                std::copy(processed_block.begin(), processed_block.end(), result.begin() + i);
            });
        }

        for (auto& t : threads) t.join();
        return result;
    }

    std::vector<std::byte> RandomDeltaEncryption::decrypt(const std::vector<std::byte>& data) {
        if (!init_vector) throw std::runtime_error("IV required for RandomDelta mode");
        auto block_size = algorithm->get_block_size();
        std::vector<std::byte> result = data;
        auto iv = init_vector.value();
        if (iv.size() < block_size) iv.resize(block_size);

        std::vector<std::byte> random_delta(iv.begin() + iv.size() / 2, iv.end());
        std::vector<std::byte> current_iv = iv;

        std::vector<std::thread> threads;
        std::mutex result_mutex;

        for (size_t i = 0; i < result.size(); i += block_size) {
            threads.emplace_back([&, i, block_size]() {
                current_iv = bits_functions::add_byte_vectors(current_iv, random_delta);
                size_t end_index = std::min(i + block_size, result.size());
                std::vector<std::byte> block(result.begin() + i, result.begin() + end_index);
                std::vector<std::byte> processed_block = algorithm->decrypt(block);
                std::vector<std::byte> xor_block = bits_functions::xor_vectors(current_iv, processed_block, block.size());

                std::lock_guard<std::mutex> lock(result_mutex);
                std::copy(xor_block.begin(), xor_block.end(), result.begin() + i);
            });
        }

        for (auto& t : threads) t.join();
        return result;
    }

}