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

namespace symmerical_algorithm {

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
        virtual void set_key(const std::vector<std::byte>& key) = 0;
        virtual std::vector<std::byte> encrypt(const std::vector<std::byte>& block) = 0;
        virtual std::vector<std::byte> decrypt(const std::vector<std::byte>& block) = 0;
        virtual size_t get_block_size() = 0;
    };

    class TestEncyption: public SymmetricEncryption {
    public:
        void set_key(const std::vector<std::byte>& key) override;
        std::vector<std::byte> encrypt(const std::vector<std::byte>& block) override;
        std::vector<std::byte> decrypt(const std::vector<std::byte>& block) override;
        size_t get_block_size() override;
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
        SymmetricAlgorithm(std::vector<std::byte> key_,
                           EncryptionModes encryption_mode_,
                           PaddingModes padding_mode_,
                           std::optional<std::vector<std::byte>> init_vector_ = std::nullopt,
                           std::vector<std::any> params_ = {},
                           std::unique_ptr<SymmetricEncryption> algorithm_ = nullptr);

        ~SymmetricAlgorithm() = default;

        std::future<std::vector<std::byte>> encrypt(const std::vector<std::byte>& data);
        std::future<void> encrypt(const std::filesystem::path& input_file, const std::filesystem::path& output_file);

        std::future<std::vector<std::byte>> decrypt(const std::vector<std::byte>& data);
        std::future<void> decrypt(const std::filesystem::path& input_file, const std::filesystem::path& output_file);

        std::vector<std::byte> ECB(const std::vector<std::byte>& data, bool encrypt);
        std::vector<std::byte> CBC(const std::vector<std::byte>& data, bool encrypt);
        std::vector<std::byte> PCBC(const std::vector<std::byte>& data, bool encrypt);
        std::vector<std::byte> CFB(const std::vector<std::byte>& data, bool encrypt);
        std::vector<std::byte> OFB(const std::vector<std::byte>& data, bool encrypt);
        std::vector<std::byte> CTR(const std::vector<std::byte>& data, bool encrypt);
        std::vector<std::byte> RandomDelta(const std::vector<std::byte>& data, bool encrypt);

        void padding(std::vector<std::byte>& data, size_t n_bytes);

        void remove_padding(std::vector<std::byte>& data);
    };

} // namespace Crypto
