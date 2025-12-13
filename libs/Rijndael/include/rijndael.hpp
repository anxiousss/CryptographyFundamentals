#include "symmetric_context.hpp"
#include "galois_fields.hpp"

namespace rijndael {
    class Rijndael: public symmetric_context::SymmetricAlgorithm {
    private:
        std::vector<std::byte> sub_bytes(std::vector<std::byte>& state);
        std::vector<std::byte> shift_rows(std::vector<std::byte>& state);
        std::vector<std::byte> mix_columns(std::vector<std::byte>& state);
        std::vector<std::byte> add_round_key(std::vector<std::byte>& state);
        std::vector<std::byte> inv_sub_bytes(std::vector<std::byte>& state);
        std::vector<std::byte> inv_shift_rows(std::vector<std::byte>& state);
        std::vector<std::byte> inv_mix_columns(std::vector<std::byte>& state);
        std::vector<std::byte> inv_add_round_key(std::vector<std::byte>& state);
        std::vector<std::byte> key_expansion();
    public:
        Rijndael(std::vector<std::byte>& key, size_t block_size, size_t index);
        Rijndael(std::vector<std::byte>& key, size_t block_size, galois_fields::GaloisField polynominal);
        void set_key(const std::vector<std::byte> &key) override;
        std::vector<std::byte> encrypt(const std::vector<std::byte> &block) override;
        std::vector<std::byte> decrypt(const std::vector<std::byte> &block) override;
        size_t get_block_size() override;
    };
}