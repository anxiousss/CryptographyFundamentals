#pragma once

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
#include <fstream>
#include <stdexcept>
#include "bits_functions.hpp"

namespace symmetric_context {

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



    class PaddingMode {
     private:
        PaddingModes mode;
    public:
        PaddingMode(PaddingModes mode_): mode(mode_) {};
        void padding(std::vector<std::byte>& data, size_t n_bytes);
        void remove_padding(std::vector<std::byte>& data);
    };


    class RoundKeyGeneration {
    public:
        virtual ~RoundKeyGeneration() = default;
        virtual std::vector<std::vector<std::byte>> key_extension(const std::vector<std::byte>& key, size_t rounds) = 0;
    };

    class EncryptionTransformation {
    public:
        virtual ~EncryptionTransformation() = default;
        virtual std::vector<std::byte> encrypt(const std::vector<std::byte>& block,
                                               const std::vector<std::byte>& round_key) = 0;
    };

    class SymmetricAlgorithm {
    public:
        virtual ~SymmetricAlgorithm() = default;
        virtual void set_key(const std::vector<std::byte>& key) = 0;
        virtual std::vector<std::byte> encrypt(const std::vector<std::byte>& block) = 0;
        virtual std::vector<std::byte> decrypt(const std::vector<std::byte>& block) = 0;
        virtual size_t get_block_size() = 0;
    };

    class EncryptionMode {
    private:
        std::vector<std::byte> key;
        PaddingMode padding_mode;
        std::optional<std::vector<std::byte>> init_vector;
        std::unique_ptr<SymmetricAlgorithm> algorithm;
    public:
        EncryptionModes encryption_mode;
        EncryptionMode(std::vector<std::byte> key_, EncryptionModes encryption_mode_, PaddingModes padding_mode_,
                       std::optional<std::vector<std::byte>> init_vector_ = std::nullopt,
                       std::unique_ptr<SymmetricAlgorithm> algorithm_ = nullptr):
        key(std::move(key_)), encryption_mode(encryption_mode_), padding_mode(padding_mode_),
        init_vector(std::move(init_vector_)),
        algorithm(std::move(algorithm_)) {};

        std::vector<std::byte> ECB_encrypt(const std::vector<std::byte>& data);
        std::vector<std::byte> ECB_decrypt(const std::vector<std::byte>& data);
        std::vector<std::byte> CBC_encrypt(const std::vector<std::byte>& data);
        std::vector<std::byte> CBC_decrypt(const std::vector<std::byte>& data);
        std::vector<std::byte> PCBC_encrypt(const std::vector<std::byte>& data);
        std::vector<std::byte> PCBC_decrypt(const std::vector<std::byte>& data);
        std::vector<std::byte> CFB_encrypt(const std::vector<std::byte>& data);
        std::vector<std::byte> CFB_decrypt(const std::vector<std::byte>& data);
        std::vector<std::byte> OFB_encrypt(const std::vector<std::byte>& data);
        std::vector<std::byte> OFB_decrypt(const std::vector<std::byte>& data);
        std::vector<std::byte> CTR_encrypt(const std::vector<std::byte>& data);
        std::vector<std::byte> CTR_decrypt(const std::vector<std::byte>& data);
        std::vector<std::byte> RandomDelta_encrypt(const std::vector<std::byte>& data);
        std::vector<std::byte> RandomDelta_decrypt(const std::vector<std::byte>& data);

    };

    class SymmetricContext {
    private:
        EncryptionMode encryption_mode;
        std::vector<std::any> params;
        mutable std::mutex mutex;

    public:
        SymmetricContext(std::vector<std::byte> key_,
                           EncryptionModes encryption_mode_,
                           PaddingModes padding_mode_,
                           std::optional<std::vector<std::byte>> init_vector_ = std::nullopt,
                           std::vector<std::any> params_ = {},
                           std::unique_ptr<SymmetricAlgorithm> algorithm_ = nullptr);

        ~SymmetricContext() = default;

        std::future<std::vector<std::byte>> encrypt(const std::vector<std::byte>& data);
        std::future<void> encrypt(const std::filesystem::path& input_file,
                                  std::optional<std::filesystem::path>& output_file);

        std::future<std::vector<std::byte>> decrypt(const std::vector<std::byte>& data);
        std::future<void> decrypt(const std::filesystem::path& input_file,
                                  std::optional<std::filesystem::path>& output_file);
    };

}
