#include "bits_functions.hpp"
#include "symmetric_context.hpp"
#include "galois_fields.hpp"


namespace rijndael {
    inline std::vector<std::byte> irreducible_polynomials =
            galois_fields::polynomials[8];

    void print_state(const std::vector<std::vector<std::byte>>& state,
                     const std::string& title = "State");

    std::vector<std::vector<std::byte>> to_state(const std::vector<std::byte>& block);

    class Operations {
    public:
        Operations(std::byte poly, size_t block_size_);
        virtual ~Operations() {}

        std::byte mod;
        size_t block_size;
        std::array<std::byte, 256> SBOX;
        std::array<std::byte, 256> INV_SBOX;

        std::vector<std::vector<std::byte>> mix_colums_coefficients = {
                {std::byte{0x02}, std::byte{0x03}, std::byte{0x01}, std::byte{0x01}},
                {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x01}},
                {std::byte{0x01}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03}},
                {std::byte{0x03}, std::byte{0x01}, std::byte{0x01}, std::byte{0x02}}
        };

        std::vector<std::vector<std::byte>> inv_mix_columns_coefficients = {
                {std::byte{0x0E}, std::byte{0x0B}, std::byte{0x0D}, std::byte{0x09}},
                {std::byte{0x09}, std::byte{0x0E}, std::byte{0x0B}, std::byte{0x0D}},
                {std::byte{0x0D}, std::byte{0x09}, std::byte{0x0E}, std::byte{0x0B}},
                {std::byte{0x0B}, std::byte{0x0D}, std::byte{0x09}, std::byte{0x0E}}
        };


        std::array<std::byte, 256> generate_sbox(std::byte polynomial);
        std::array<std::byte, 256> generate_inv_sbox(std::byte polynomial);

        void print_sbox(const std::array<std::byte, 256>& sbox, const std::string& name = "SBOX");

        std::vector<std::byte> sub_word(std::vector<std::byte>& word);

        std::vector<std::vector<std::byte>> sub_bytes(std::vector<std::vector<std::byte>>& state);
        std::vector<std::vector<std::byte>> shift_rows(std::vector<std::vector<std::byte>>& state);
        std::vector<std::vector<std::byte>> mix_columns(std::vector<std::vector<std::byte>>& state);
        std::vector<std::vector<std::byte>> add_round_key(std::vector<std::vector<std::byte>>& state,
                                                          std::vector<std::byte> round_key);
        std::vector<std::vector<std::byte>> inv_sub_bytes(std::vector<std::vector<std::byte>>& state);
        std::vector<std::vector<std::byte>> inv_shift_rows(std::vector<std::vector<std::byte>>& state);
        std::vector<std::vector<std::byte>> inv_mix_columns(std::vector<std::vector<std::byte>>& state);
    };


    class RijndaelRoundKeyGenerator : public symmetric_context::RoundKeyGeneration {
    private:
        std::vector<std::byte> Rcon;
        std::byte mod;
    public:
        size_t block_size;
        RijndaelRoundKeyGenerator(size_t block_size_, const std::byte& polynomial);
        std::vector<std::vector<std::byte>> key_extension(const std::vector<std::byte> &key,
                                                          size_t rounds) override;

    };


    class Rijndael: public symmetric_context::SymmetricAlgorithm {
    private:
        std::vector<std::byte> key;
        size_t block_size;
        std::byte mod;
        std::shared_ptr<Operations> operations;
        std::shared_ptr<symmetric_context::RoundKeyGeneration> round_key_generator;
        std::vector<std::vector<std::byte>> round_keys;
        size_t rounds;

    public:
        Rijndael(std::vector<std::byte>& key_, size_t block_size_, size_t index_);
        Rijndael(std::vector<std::byte>& key, size_t block_size, std::byte polynominal);
        void set_key(const std::vector<std::byte> &key) override;
        std::vector<std::byte> encrypt(const std::vector<std::byte> &block) override;
        std::vector<std::byte> decrypt(const std::vector<std::byte> &block) override;
        size_t get_block_size() override;
    };
}