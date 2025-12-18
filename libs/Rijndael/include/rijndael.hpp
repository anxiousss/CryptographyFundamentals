#include "bits_functions.hpp"
#include "symmetric_context.hpp"
#include "galois_fields.hpp"

/*
namespace rijndael {
    inline std::vector<std::vector<std::byte>> irreducible_polynomials =
            galois_fields::GaloisField::find_irreducible_polynomials()[8];


    std::array<std::byte, 256> generate_sbox(std::vector<std::byte> polynomial);
    std::array<std::byte, 256> generate_inv_sbox();
    void print_box(std::array<std::byte, 256> box);


    class RijndaelRoundKeyGenerator : public symmetric_context::RoundKeyGeneration {
    private:
        std::vector<std::vector<std::byte>> Rcon;
    public:
        size_t block_size;
        RijndaelRoundKeyGenerator(size_t block_size_, const std::vector<std::byte>& polynomial);
        std::vector<std::vector<std::byte>> key_extension(const std::vector<std::byte> &key,
                                                          size_t rounds) override;

    };

    class RijndaelRoundTransformation: public symmetric_context::EncryptionTransformation {
    private:

        std::vector<std::byte> sub_bytes(std::vector<std::byte>& state);
        std::vector<std::byte> shift_rows(std::vector<std::byte>& state);
        std::vector<std::byte> mix_columns(std::vector<std::byte>& state);
        std::vector<std::byte> add_round_key(std::vector<std::byte>& state);
        std::vector<std::byte> inv_sub_bytes(std::vector<std::byte>& state);
        std::vector<std::byte> inv_shift_rows(std::vector<std::byte>& state);
        std::vector<std::byte> inv_mix_columns(std::vector<std::byte>& state);
        std::vector<std::byte> inv_add_round_key(std::vector<std::byte>& state);

        std::vector<std::byte> encrypt(const std::vector<std::byte>& block,
                                       const std::vector<std::byte>& round_key) override;

        std::vector<std::byte> decrypt(const std::vector<std::byte>& block,
                                       const std::vector<std::byte>& round_key);

    public:
        RijndaelRoundTransformation(std::vector<std::byte> polynomial);
        std::array<std::byte, 256> SBOX;
        std::array<std::byte, 256> INV_SBOX;
    };


    class Rijndael: public symmetric_context::SymmetricAlgorithm {
    private:
        std::vector<std::byte> key;
        size_t block_size;
        std::vector<std::byte> polynominal;
        std::shared_ptr<symmetric_context::RoundKeyGeneration> round_key_generator;
        std::shared_ptr<symmetric_context::EncryptionTransformation> encryption_transformer;
        std::vector<std::vector<std::byte>> round_keys;
        size_t rounds;

    public:
        Rijndael(std::vector<std::byte>& key_, size_t block_size_, size_t index_);
        Rijndael(std::vector<std::byte>& key, size_t block_size, std::vector<std::byte> polynominal);
        void set_key(const std::vector<std::byte> &key) override;
        std::vector<std::byte> encrypt(const std::vector<std::byte> &block) override;
        std::vector<std::byte> decrypt(const std::vector<std::byte> &block) override;
        size_t get_block_size() override;
    };
}*/