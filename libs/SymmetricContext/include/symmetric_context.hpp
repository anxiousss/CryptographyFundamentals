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
#include <atomic>
#include <random>
#include "bits_functions.hpp"

namespace symmetric_context {

    enum class EncryptionModes {
        ECB,
        CBC,
        PCBC,
        CFB,
        OFB,
        CTR,
        RandomDelta
    };

    enum class PaddingModes {
        Zeros,
        ANSIX_923,
        PKCS7,
        ISO_10126
    };

    class PaddingMode {
    public:
        virtual ~PaddingMode() = default;
        virtual void padding(std::vector<std::byte>& data, size_t n_bytes) = 0;
        virtual void remove_padding(std::vector<std::byte>& data) = 0;
    };

    class ZerosPadding : public PaddingMode {
    public:
        void padding(std::vector<std::byte>& data, size_t target_size) override;
        void remove_padding(std::vector<std::byte>& data) override;
    };

    class ANSIX923Padding : public PaddingMode {
    public:
        void padding(std::vector<std::byte>& data, size_t target_size) override;
        void remove_padding(std::vector<std::byte>& data) override;
    };

    class PKCS7Padding : public PaddingMode {
    public:
        void padding(std::vector<std::byte>& data, size_t target_size) override;
        void remove_padding(std::vector<std::byte>& data) override;
    };

    class ISO10126Padding : public PaddingMode {
    public:
        void padding(std::vector<std::byte>& data, size_t target_size) override;
        void remove_padding(std::vector<std::byte>& data) override;
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

    class SubstitutionLayer {
    public:
        virtual ~SubstitutionLayer() = default;
        virtual std::vector<std::byte> forward(const std::vector<std::byte>& block) = 0;
        virtual std::vector<std::byte> inverse(const std::vector<std::byte>& block) = 0;
    };

    class PermutationLayer {
    public:
        virtual ~PermutationLayer() = default;
        virtual std::vector<std::byte> forward(const std::vector<std::byte>& block) = 0;
        virtual std::vector<std::byte> inverse(const std::vector<std::byte>& block) = 0;
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
    protected:
        std::vector<std::byte> key;
        std::optional<std::vector<std::byte>> init_vector;
        std::unique_ptr<SymmetricAlgorithm> algorithm;

    public:
        EncryptionMode(std::vector<std::byte> key_,
                       std::optional<std::vector<std::byte>> init_vector_,
                       std::unique_ptr<SymmetricAlgorithm> algorithm_)
                : key(std::move(key_))
                , init_vector(std::move(init_vector_))
                , algorithm(std::move(algorithm_)) {}

        virtual ~EncryptionMode() = default;

        virtual std::vector<std::byte> encrypt(const std::vector<std::byte>& data) = 0;
        virtual std::vector<std::byte> decrypt(const std::vector<std::byte>& data) = 0;

        size_t get_block_size() { return algorithm->get_block_size(); }
    };

    class ECBEncryption : public EncryptionMode {
    public:
        using EncryptionMode::EncryptionMode;
        std::vector<std::byte> encrypt(const std::vector<std::byte>& data) override;
        std::vector<std::byte> decrypt(const std::vector<std::byte>& data) override;
    };

    class CBCEncryption : public EncryptionMode {
    public:
        using EncryptionMode::EncryptionMode;
        std::vector<std::byte> encrypt(const std::vector<std::byte>& data) override;
        std::vector<std::byte> decrypt(const std::vector<std::byte>& data) override;
    };

    class PCBCEncryption : public EncryptionMode {
    public:
        using EncryptionMode::EncryptionMode;
        std::vector<std::byte> encrypt(const std::vector<std::byte>& data) override;
        std::vector<std::byte> decrypt(const std::vector<std::byte>& data) override;
    };

    class CFBEncryption : public EncryptionMode {
    public:
        using EncryptionMode::EncryptionMode;
        std::vector<std::byte> encrypt(const std::vector<std::byte>& data) override;
        std::vector<std::byte> decrypt(const std::vector<std::byte>& data) override;
    };

    class OFBEncryption : public EncryptionMode {
    public:
        using EncryptionMode::EncryptionMode;
        std::vector<std::byte> encrypt(const std::vector<std::byte>& data) override;
        std::vector<std::byte> decrypt(const std::vector<std::byte>& data) override;
    };

    class CTREncryption : public EncryptionMode {
    public:
        using EncryptionMode::EncryptionMode;
        std::vector<std::byte> encrypt(const std::vector<std::byte>& data) override;
        std::vector<std::byte> decrypt(const std::vector<std::byte>& data) override;
    };

    class RandomDeltaEncryption : public EncryptionMode {
    public:
        using EncryptionMode::EncryptionMode;
        std::vector<std::byte> encrypt(const std::vector<std::byte>& data) override;
        std::vector<std::byte> decrypt(const std::vector<std::byte>& data) override;
    };

    class SymmetricContext {
    private:
        std::unique_ptr<EncryptionMode> encryption_mode;
        std::unique_ptr<PaddingMode> padding_mode;
        std::vector<std::any> params;
        mutable std::mutex mutex;

        std::vector<std::byte> apply_padding(const std::vector<std::byte>& data);
        std::vector<std::byte> remove_padding(const std::vector<std::byte>& data);

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