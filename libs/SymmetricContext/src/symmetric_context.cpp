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

        std::vector<std::byte> original_data = data;
        data.resize(target_size);

        std::copy(original_data.begin(), original_data.end(), data.begin());

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

        size_t data_size = data.size();
        uint8_t padding_size = static_cast<uint8_t>(data.back());

        if (padding_size == 0 || padding_size > data_size) {
            return;
        }

        if (padding_size <= data_size) {
            data.resize(data_size - padding_size);
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
        if (data.empty()) {
            auto block_size = encryption_mode->get_block_size();
            std::vector<std::byte> padded_data;
            padded_data.reserve(block_size);
            padding_mode->padding(padded_data, block_size);
            return padded_data;
        }

        auto block_size = encryption_mode->get_block_size();
        std::vector<std::byte> padded_data = data;


        size_t required_size = ((data.size() + block_size - 1) / block_size) * block_size;
        if (required_size == data.size()) {
            required_size += block_size;
        }

        padding_mode->padding(padded_data, required_size);

        if (padded_data.size() % block_size != 0) {
            std::cout << "ERROR: Padding failed! Size " << padded_data.size()
                      << " is not multiple of block size " << block_size << std::endl;
        }

        return padded_data;
    }

    std::vector<std::byte> SymmetricContext::remove_padding(const std::vector<std::byte>& data) {
        if (data.empty()) return data;

        std::vector<std::byte> unpadded_data = data;
        padding_mode->remove_padding(unpadded_data);
        return unpadded_data;
    }

    std::future<std::vector<std::byte>> SymmetricContext::encrypt(const std::vector<std::byte>& data) {
        return std::async(std::launch::async, [this, data]() -> std::vector<std::byte> {
            std::lock_guard<std::mutex> lock(mutex);
            if (data.empty()) return data;

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

            size_t block_size = encryption_mode->get_block_size();
            size_t buffer_size = 4096;
            buffer_size = (buffer_size / block_size) * block_size;
            if (buffer_size == 0) buffer_size = block_size;

            in_file.seekg(0, std::ios::end);
            size_t file_size = in_file.tellg();
            in_file.seekg(0, std::ios::beg);

            if (file_size == 0) {
                auto padded_empty = apply_padding({});
                out_file.write(reinterpret_cast<const char*>(padded_empty.data()), padded_empty.size());
                std::cout << "Encrypted empty file: " << input_file << " -> " << actual_output_path << std::endl;
                return;
            }

            std::vector<std::byte> buffer(buffer_size);
            size_t total_processed = 0;

            while (total_processed < file_size) {
                size_t remaining = file_size - total_processed;
                size_t to_read = std::min(buffer_size, remaining);

                in_file.read(reinterpret_cast<char*>(buffer.data()), to_read);
                size_t bytes_read = in_file.gcount();

                if (bytes_read == 0) break;

                total_processed += bytes_read;

                if (total_processed == file_size) {
                    std::vector<std::byte> last_chunk(buffer.begin(), buffer.begin() + bytes_read);
                    auto padded_chunk = apply_padding(last_chunk);
                    auto encrypted_data = encryption_mode->encrypt(padded_chunk);
                    out_file.write(reinterpret_cast<const char*>(encrypted_data.data()), encrypted_data.size());
                } else {
                    std::vector<std::byte> chunk(buffer.begin(), buffer.begin() + bytes_read);
                    auto encrypted_data = encryption_mode->encrypt(chunk);
                    out_file.write(reinterpret_cast<const char*>(encrypted_data.data()), encrypted_data.size());
                }
            }

            std::cout << "File encrypted: " << input_file << " -> " << actual_output_path << std::endl;
        });
    }

    std::future<std::vector<std::byte>> SymmetricContext::decrypt(const std::vector<std::byte>& data) {
        return std::async(std::launch::async, [this, data]() -> std::vector<std::byte> {
            std::lock_guard<std::mutex> lock(mutex);
            if (data.empty()) return data;

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

            size_t block_size = encryption_mode->get_block_size();
            size_t buffer_size = 4096;
            buffer_size = (buffer_size / block_size) * block_size;
            if (buffer_size == 0) buffer_size = block_size;
            in_file.seekg(0, std::ios::end);
            size_t file_size = in_file.tellg();
            in_file.seekg(0, std::ios::beg);

            if (file_size == 0) {
                std::cout << "Input file is empty: " << input_file << std::endl;
                return;
            }

            std::vector<std::byte> buffer(buffer_size);
            size_t total_processed = 0;
            std::vector<std::byte> final_chunk;

            while (total_processed < file_size) {
                size_t remaining = file_size - total_processed;
                size_t to_read = std::min(buffer_size, remaining);

                in_file.read(reinterpret_cast<char *>(buffer.data()), to_read);
                size_t bytes_read = in_file.gcount();

                if (bytes_read == 0) break;
                total_processed += bytes_read;

                std::vector<std::byte> chunk(buffer.begin(), buffer.begin() + bytes_read);
                auto decrypted_chunk = encryption_mode->decrypt(chunk);

                if (total_processed == file_size) {
                    auto unpadded_data = remove_padding(decrypted_chunk);
                    out_file.write(reinterpret_cast<const char *>(unpadded_data.data()), unpadded_data.size());
                } else {
                    out_file.write(reinterpret_cast<const char *>(decrypted_chunk.data()), decrypted_chunk.size());
                }
            }

            std::cout << "File decrypted: " << input_file << " -> " << actual_output_path << std::endl;
        });
    }

    std::vector<std::byte> ECBEncryption::encrypt(const std::vector<std::byte>& data) {
        if (data.empty()) return data;

        auto block_size = algorithm->get_block_size();
        std::vector<std::byte> result = data;

        const size_t num_blocks = data.size() / block_size;
        if (num_blocks == 0) return data;

        const size_t num_threads = std::min(
                static_cast<size_t>(std::thread::hardware_concurrency()),
                num_blocks
        );

        std::vector<std::thread> threads;
        const size_t blocks_per_thread = num_blocks / num_threads;
        const size_t extra_blocks = num_blocks % num_threads;

        size_t start_block = 0;
        for (size_t t = 0; t < num_threads; ++t) {
            size_t end_block = start_block + blocks_per_thread + (t < extra_blocks ? 1 : 0);

            threads.emplace_back([&, start_block, end_block, block_size]() {
                for (size_t block_idx = start_block; block_idx < end_block; ++block_idx) {
                    size_t i = block_idx * block_size;
                    size_t end_index = i + block_size;
                    std::vector<std::byte> block(result.begin() + i, result.begin() + end_index);
                    auto processed_block = algorithm->encrypt(block);
                    std::copy(processed_block.begin(), processed_block.end(), result.begin() + i);
                }
            });

            start_block = end_block;
        }

        for (auto& t : threads) t.join();

        return result;
    }

    std::vector<std::byte> ECBEncryption::decrypt(const std::vector<std::byte>& data) {
        if (data.empty()) return data;

        auto block_size = algorithm->get_block_size();
        std::vector<std::byte> result = data;

        const size_t num_blocks = data.size() / block_size;
        if (num_blocks == 0) return data;

        const size_t num_threads = std::min(
                static_cast<size_t>(std::thread::hardware_concurrency()),
                num_blocks
        );

        std::vector<std::thread> threads;
        const size_t blocks_per_thread = num_blocks / num_threads;
        const size_t extra_blocks = num_blocks % num_threads;

        size_t start_block = 0;
        for (size_t t = 0; t < num_threads; ++t) {
            size_t end_block = start_block + blocks_per_thread + (t < extra_blocks ? 1 : 0);

            threads.emplace_back([&, start_block, end_block, block_size]() {
                for (size_t block_idx = start_block; block_idx < end_block; ++block_idx) {
                    size_t i = block_idx * block_size;
                    size_t end_index = i + block_size;
                    std::vector<std::byte> block(result.begin() + i, result.begin() + end_index);
                    auto processed_block = algorithm->decrypt(block);
                    std::copy(processed_block.begin(), processed_block.end(), result.begin() + i);
                }
            });

            start_block = end_block;
        }

        for (auto& t : threads) t.join();

        return result;
    }

    std::vector<std::byte> CBCEncryption::encrypt(const std::vector<std::byte>& data) {
        if (data.empty()) return data;

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
        if (data.empty()) return data;

        if (!init_vector) {
            throw std::runtime_error("Initialization vector is required for CBC mode");
        }

        auto block_size = algorithm->get_block_size();
        std::vector<std::byte> result(data.size());
        auto iv = init_vector.value();
        if (iv.size() < block_size) iv.resize(block_size);

        const size_t num_blocks = data.size() / block_size;
        if (num_blocks == 0) return data;

        const size_t num_threads = std::min(
                static_cast<size_t>(std::thread::hardware_concurrency()),
                num_blocks
        );

        std::vector<std::thread> threads;
        const size_t blocks_per_thread = num_blocks / num_threads;
        const size_t extra_blocks = num_blocks % num_threads;

        std::mutex result_mutex;
        size_t start_block = 0;
        for (size_t t = 0; t < num_threads; ++t) {
            size_t end_block = start_block + blocks_per_thread + (t < extra_blocks ? 1 : 0);

            threads.emplace_back([&, start_block, end_block, block_size, iv]() {
                std::vector<std::byte> local_prev_block;

                if (start_block == 0) {
                    local_prev_block = iv;
                } else {
                    size_t prev_block_idx = start_block - 1;
                    size_t prev_index = prev_block_idx * block_size;
                    local_prev_block = std::vector<std::byte>(
                            data.begin() + prev_index,
                            data.begin() + prev_index + block_size
                    );
                }

                for (size_t block_idx = start_block; block_idx < end_block; ++block_idx) {
                    size_t i = block_idx * block_size;
                    size_t end_index = i + block_size;

                    std::vector<std::byte> encrypted_block(data.begin() + i, data.begin() + end_index);
                    auto decrypted_block = algorithm->decrypt(encrypted_block);
                    auto plain_block = bits_functions::xor_vectors(decrypted_block, local_prev_block, block_size);

                    {
                        std::lock_guard<std::mutex> lock(result_mutex);
                        std::copy(plain_block.begin(), plain_block.end(), result.begin() + i);
                    }

                    local_prev_block = encrypted_block;
                }
            });

            start_block = end_block;
        }

        for (auto& t : threads) t.join();
        return result;
    }

    std::vector<std::byte> PCBCEncryption::encrypt(const std::vector<std::byte>& data) {
        if (data.empty()) return data;

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
        if (data.empty()) return data;

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
        if (data.empty()) return data;

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
        if (data.empty()) return data;

        if (!init_vector) throw std::runtime_error("IV required for CFB mode");
        auto block_size = algorithm->get_block_size();
        std::vector<std::byte> result = data;
        auto iv = init_vector.value();
        if (iv.size() < block_size) iv.resize(block_size);

        const size_t num_blocks = data.size() / block_size;
        if (num_blocks == 0) return data;

        const size_t num_threads = std::min(
                static_cast<size_t>(std::thread::hardware_concurrency()),
                num_blocks
        );

        std::vector<std::thread> threads;
        const size_t blocks_per_thread = num_blocks / num_threads;
        const size_t extra_blocks = num_blocks % num_threads;

        std::mutex result_mutex;
        size_t start_block = 0;
        for (size_t t = 0; t < num_threads; ++t) {
            size_t end_block = start_block + blocks_per_thread + (t < extra_blocks ? 1 : 0);

            threads.emplace_back([&, start_block, end_block, block_size, iv]() {
                std::vector<std::byte> local_feedback;

                if (start_block == 0) {
                    local_feedback = iv;
                } else {
                    size_t prev_block_idx = start_block - 1;
                    size_t prev_index = prev_block_idx * block_size;
                    local_feedback = std::vector<std::byte>(
                            data.begin() + prev_index,
                            data.begin() + prev_index + block_size
                    );
                }

                for (size_t block_idx = start_block; block_idx < end_block; ++block_idx) {
                    size_t i = block_idx * block_size;
                    size_t end_index = i + block_size;

                    std::vector<std::byte> block(result.begin() + i, result.begin() + end_index);
                    auto encrypted_feedback = algorithm->encrypt(local_feedback);
                    auto plain_block = bits_functions::xor_vectors(block, encrypted_feedback, block.size());

                    {
                        std::lock_guard<std::mutex> lock(result_mutex);
                        std::copy(plain_block.begin(), plain_block.end(), result.begin() + i);
                    }

                    local_feedback = block;
                }
            });

            start_block = end_block;
        }

        for (auto& t : threads) t.join();
        return result;
    }

    std::vector<std::byte> OFBEncryption::encrypt(const std::vector<std::byte>& data) {
        if (data.empty()) return data;

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
        if (data.empty()) return data;

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
        if (data.empty()) return data;

        if (!init_vector) throw std::runtime_error("IV required for CTR mode");
        auto block_size = algorithm->get_block_size();
        std::vector<std::byte> result = data;
        auto iv = init_vector.value();
        if (iv.size() < block_size) iv.resize(block_size);

        const size_t num_blocks = (data.size() + block_size - 1) / block_size;
        if (num_blocks == 0) return data;

        const size_t num_threads = std::min(
                static_cast<size_t>(std::thread::hardware_concurrency()),
                num_blocks
        );

        std::vector<std::thread> threads;
        const size_t blocks_per_thread = num_blocks / num_threads;
        const size_t extra_blocks = num_blocks % num_threads;

        std::mutex result_mutex;
        size_t start_block = 0;
        for (size_t t = 0; t < num_threads; ++t) {
            size_t end_block = start_block + blocks_per_thread + (t < extra_blocks ? 1 : 0);

            threads.emplace_back([&, start_block, end_block, block_size, iv]() {
                for (size_t block_idx = start_block; block_idx < end_block; ++block_idx) {
                    size_t i = block_idx * block_size;
                    size_t end_index = std::min(i + block_size, result.size());
                    size_t current_block_size = end_index - i;

                    std::vector<std::byte> block(result.begin() + i, result.begin() + end_index);

                    auto counter_value = bits_functions::add_number_to_bytes(iv, block_idx);
                    auto encrypted_counter = algorithm->encrypt(counter_value);

                    std::vector<std::byte> keystream_block(encrypted_counter.begin(),
                                                           encrypted_counter.begin() + current_block_size);
                    auto processed_block = bits_functions::xor_vectors(block, keystream_block, current_block_size);

                    std::lock_guard<std::mutex> lock(result_mutex);
                    std::copy(processed_block.begin(), processed_block.end(), result.begin() + i);
                }
            });

            start_block = end_block;
        }

        for (auto& t : threads) t.join();
        return result;
    }

    std::vector<std::byte> CTREncryption::decrypt(const std::vector<std::byte>& data) {
        return encrypt(data);
    }

    std::vector<std::byte> RandomDeltaEncryption::encrypt(const std::vector<std::byte>& data) {
        if (data.empty()) return data;

        if (!init_vector) throw std::runtime_error("IV required for RandomDelta mode");
        auto block_size = algorithm->get_block_size();
        std::vector<std::byte> result = data;
        auto iv = init_vector.value();
        if (iv.size() < block_size) iv.resize(block_size);

        std::vector<std::byte> random_delta(iv.begin() + iv.size() / 2, iv.end());

        const size_t num_blocks = data.size() / block_size;
        if (num_blocks == 0) return data;

        const size_t num_threads = std::min(
                static_cast<size_t>(std::thread::hardware_concurrency()),
                num_blocks
        );

        std::vector<std::thread> threads;
        const size_t blocks_per_thread = num_blocks / num_threads;
        const size_t extra_blocks = num_blocks % num_threads;

        std::mutex result_mutex;
        size_t start_block = 0;
        for (size_t t = 0; t < num_threads; ++t) {
            size_t end_block = start_block + blocks_per_thread + (t < extra_blocks ? 1 : 0);

            threads.emplace_back([&, start_block, end_block, block_size, iv, random_delta]() {
                std::vector<std::byte> current_iv = iv;


                for (size_t i = 0; i < start_block; ++i) {
                    current_iv = bits_functions::add_byte_vectors(current_iv, random_delta);
                }

                for (size_t block_idx = start_block; block_idx < end_block; ++block_idx) {
                    size_t i = block_idx * block_size;
                    size_t end_index = i + block_size;

                    std::vector<std::byte> block(result.begin() + i, result.begin() + end_index);
                    std::vector<std::byte> xor_block = bits_functions::xor_vectors(current_iv, block, block.size());
                    std::vector<std::byte> processed_block = algorithm->encrypt(xor_block);

                    {
                        std::lock_guard<std::mutex> lock(result_mutex);
                        std::copy(processed_block.begin(), processed_block.end(), result.begin() + i);
                    }

                    current_iv = bits_functions::add_byte_vectors(current_iv, random_delta);
                }
            });

            start_block = end_block;
        }

        for (auto& t : threads) t.join();
        return result;
    }

    std::vector<std::byte> RandomDeltaEncryption::decrypt(const std::vector<std::byte>& data) {
        if (data.empty()) return data;

        if (!init_vector) throw std::runtime_error("IV required for RandomDelta mode");
        auto block_size = algorithm->get_block_size();
        std::vector<std::byte> result = data;
        auto iv = init_vector.value();
        if (iv.size() < block_size) iv.resize(block_size);

        std::vector<std::byte> random_delta(iv.begin() + iv.size() / 2, iv.end());

        const size_t num_blocks = data.size() / block_size;
        if (num_blocks == 0) return data;

        const size_t num_threads = std::min(
                static_cast<size_t>(std::thread::hardware_concurrency()),
                num_blocks
        );

        std::vector<std::thread> threads;
        const size_t blocks_per_thread = num_blocks / num_threads;
        const size_t extra_blocks = num_blocks % num_threads;

        std::mutex result_mutex;
        size_t start_block = 0;
        for (size_t t = 0; t < num_threads; ++t) {
            size_t end_block = start_block + blocks_per_thread + (t < extra_blocks ? 1 : 0);

            threads.emplace_back([&, start_block, end_block, block_size, iv, random_delta]() {
                std::vector<std::byte> current_iv = iv;

                for (size_t i = 0; i < start_block; ++i) {
                    current_iv = bits_functions::add_byte_vectors(current_iv, random_delta);
                }

                for (size_t block_idx = start_block; block_idx < end_block; ++block_idx) {
                    size_t i = block_idx * block_size;
                    size_t end_index = i + block_size;

                    std::vector<std::byte> block(result.begin() + i, result.begin() + end_index);
                    std::vector<std::byte> processed_block = algorithm->decrypt(block);
                    std::vector<std::byte> xor_block = bits_functions::xor_vectors(current_iv, processed_block, block.size());

                    {
                        std::lock_guard<std::mutex> lock(result_mutex);
                        std::copy(xor_block.begin(), xor_block.end(), result.begin() + i);
                    }

                    current_iv = bits_functions::add_byte_vectors(current_iv, random_delta);
                }
            });

            start_block = end_block;
        }

        for (auto& t : threads) t.join();
        return result;
    }

}