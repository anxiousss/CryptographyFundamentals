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
#include <iostream>
#include <bitset>

std::ostream& operator<<(std::ostream& os, std::byte b)
{
    return os << std::bitset<8>(std::to_integer<int>(b));
}


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

    ~SymmetricAlgorithm() = default;

    std::future<std::vector<std::byte>> encrypt(const std::vector<std::byte>& data);
    std::future<void> encrypt(const std::filesystem::path& input_file, const std::filesystem::path& output_file);

    std::future<std::vector<std::byte>> decrypt(const std::vector<std::byte>& data);
    std::future<void> decrypt(const std::filesystem::path& input_file, const std::filesystem::path& output_file);

private:
    std::vector<std::byte> ECB(const std::vector<std::byte>& data, bool encrypt);
    std::vector<std::byte> CBC(const std::vector<std::byte>& data, bool encrypt);
    std::vector<std::byte> PCBC(const std::vector<std::byte>& data, bool encrypt);
    std::vector<std::byte> CFB(const std::vector<std::byte>& data, bool encrypt);
    std::vector<std::byte> OFB(const std::vector<std::byte>& data, bool encrypt);
    std::vector<std::byte> CTR(const std::vector<std::byte>& data, bool encrypt);
    std::vector<std::byte> RandomDelta(const std::vector<std::byte>& data, bool encrypt);

public:
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
                break;
            case PaddingModes::ISO_10126:
                break;
        }
    }

};

int main() {
    SymmetricAlgorithm s{{}, EncryptionModes::CBC, PaddingModes::ANSIX_923};
    std::vector<std::byte> msg(2);
    msg[0] = std::byte{10};
    msg[1] = std::byte{14};
    s.padding(msg, 16);
    std::cout << msg.size() << std::endl;
    for (auto & i : msg) {
        std::cout << i << std::endl;
    }
}