#include <vector>
#include <future>
#include <optional>
#include <any>
#include <string>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <algorithm>
#include <thread>
#include <mutex>
#include <condition_variable>

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


class PaddingStrategy {
public:
    virtual ~PaddingStrategy() = default;
    virtual std::vector<std::byte> add_padding(const std::vector<std::byte>& data, size_t block_size) = 0;
    virtual std::vector<std::byte> remove_padding(const std::vector<std::byte>& data, size_t block_size) = 0;
};

class ZerosPadding : public PaddingStrategy {
public:
    std::vector<std::byte> add_padding(const std::vector<std::byte>& data, size_t block_size) override;
    std::vector<std::byte> remove_padding(const std::vector<std::byte>& data, size_t block_size) override;
};

class ANSIX923Padding : public PaddingStrategy {
public:
    std::vector<std::byte> add_padding(const std::vector<std::byte>& data, size_t block_size) override {
        std::vector<std::byte> padding_data(data);

        size_t current_size = padding_data.size();
        size_t remainder = current_size % block_size;

        if (remainder == 0) {
            std::vector<std::byte> full_block_padding(block_size, std::byte{0});
            full_block_padding[block_size - 1] = static_cast<std::byte>(block_size);
            padding_data.insert(padding_data.end(), full_block_padding.begin(), full_block_padding.end());
        } else {
            size_t n_bytes_to_add = block_size - remainder;
            padding_data.insert(padding_data.end(), n_bytes_to_add - 1, std::byte{0});
            padding_data.push_back(static_cast<std::byte>(n_bytes_to_add));
        };
        return padding_data;
    }
    std::vector<std::byte> remove_padding(const std::vector<std::byte>& data, size_t block_size) override;
};

class PKCS7Padding : public PaddingStrategy {
public:
    std::vector<std::byte> add_padding(const std::vector<std::byte>& data, size_t block_size) override;
    std::vector<std::byte> remove_padding(const std::vector<std::byte>& data, size_t block_size) override;
};

class ISO10126Padding : public PaddingStrategy {
public:
    std::vector<std::byte> add_padding(const std::vector<std::byte>& data, size_t block_size) override;
    std::vector<std::byte> remove_padding(const std::vector<std::byte>& data, size_t block_size) override;
};


class SymmetricEncryption {
public:
    virtual ~SymmetricEncryption() = default;
    virtual void set_round_keys(const std::vector<std::vector<std::byte>>& round_keys) = 0;
    virtual std::vector<std::byte> encrypt(const std::vector<std::byte>& block) const = 0;
    virtual std::vector<std::byte> decrypt(const std::vector<std::byte>& block) const = 0;
    virtual size_t get_block_size() const = 0;
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

    virtual ~SymmetricAlgorithm() = default;

    // Методы для шифрования
    virtual std::future<std::vector<std::byte>> encrypt(const std::vector<std::byte>& data) = 0;
    virtual std::future<void> encrypt(const std::filesystem::path& input_file, const std::filesystem::path& output_file) = 0;

    // Методы для дешифрования
    virtual std::future<std::vector<std::byte>> decrypt(const std::vector<std::byte>& data) = 0;
    virtual std::future<void> decrypt(const std::filesystem::path& input_file, const std::filesystem::path& output_file) = 0;
};