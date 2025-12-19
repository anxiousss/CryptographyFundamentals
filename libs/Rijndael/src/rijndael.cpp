#include "rijndael.hpp"

namespace rijndael {
    void print_state(const std::vector<std::vector<std::byte>>& state,
                     const std::string& title) {

        if (state.empty() || state[0].empty()) {
            std::cout << title << ": Empty state\n";
            return;
        }

        size_t rows = state.size();
        size_t cols = state[0].size();

        std::cout << "\n" << title << " (" << rows << "x" << cols << "):\n";

        std::cout << "   +";
        for (size_t j = 0; j < cols; ++j) {
            std::cout << "----";
        }
        std::cout << "+\n";

        for (size_t i = 0; i < rows; ++i) {
            if (rows > 4) {
                std::cout << std::setw(2) << i << " |";
            } else {
                std::cout << "   |";
            }

            for (size_t j = 0; j < cols; ++j) {
                int value = std::to_integer<int>(state[i][j]);
                std::cout << " " << std::setw(2) << std::setfill('0') << std::hex
                          << std::uppercase << value;
            }
            std::cout << " |\n";
        }

        std::cout << "   +";
        for (size_t j = 0; j < cols; ++j) {
            std::cout << "----";
        }
        std::cout << "+\n";

        std::cout << std::dec << std::nouppercase << std::setfill(' ');
    }

    std::vector<std::vector<std::byte>> to_state(const std::vector<std::byte>& block) {
        size_t Nb = block.size() / 4;
        std::vector<std::vector<std::byte>> state(4, std::vector<std::byte>(Nb));
        for (size_t i = 0; i < Nb; ++i) {
            for (size_t j = 0; j < 4; ++j) {
                state[j][i] = block[i * 4 + j];
            }
        }
        return state;
    }

    Operations::Operations(std::byte poly, size_t block_size_): mod(poly), block_size(block_size_),
        SBOX(generate_sbox(poly)), INV_SBOX(generate_inv_sbox(poly)) {
    }

    std::array<std::byte, 256> Operations::generate_sbox(std::byte polynom) {
        std::array<std::byte, 256> BOX;
        for (size_t i = 0; i < 256; ++i) {
            std::byte byte = static_cast<std::byte>(i);
            std::byte inv = galois_fields::GaloisField::multiplicative_inverse(byte, polynom);
            std::byte b = galois_fields::GaloisField::add(inv,
                                                        bits_functions::cyclic_shift_left(inv, 1));
            b = galois_fields::GaloisField::add(b, bits_functions::cyclic_shift_left(inv, 2));
            b = galois_fields::GaloisField::add(b, bits_functions::cyclic_shift_left(inv, 3));
            b = galois_fields::GaloisField::add(b, bits_functions::cyclic_shift_left(inv, 4));
            b = galois_fields::GaloisField::add(b, std::byte{0x63});
            BOX[i] = b;
        }
        return BOX;
    }

    std::array<std::byte, 256> Operations::generate_inv_sbox(std::byte polynom) {
        std::array<std::byte, 256> BOX;
        for (int i = 0; i < 256; ++i) {
            std::byte byte = static_cast<std::byte>(i);
            std::byte b = galois_fields::GaloisField::add(bits_functions::cyclic_shift_left(byte, 1),
                                                        bits_functions::cyclic_shift_left(byte, 3));
            b = galois_fields::GaloisField::add(b, bits_functions::cyclic_shift_left(byte, 6));
            b = galois_fields::GaloisField::add(b, std::byte{0x05});
            BOX[i] = galois_fields::GaloisField::multiplicative_inverse(b, polynom);
        }
        return BOX;
    }

    void Operations::print_sbox(const std::array<std::byte, 256>& sbox, const std::string& name) {
        std::cout << "\n" << name << " (16x16):\n";

        std::cout << "      ";
        for (int col = 0; col < 16; ++col) {
            std::cout << std::setw(2) << std::hex << col << " ";
        }
        std::cout << "\n";

        std::cout << "     " << std::string(48, '-') << "\n";

        for (int row = 0; row < 16; ++row) {
            std::cout << std::hex << std::setw(2) << row << " | ";

            for (int col = 0; col < 16; ++col) {
                int index = row * 16 + col;
                int value = std::to_integer<int>(sbox[index]);
                std::cout << std::setw(2) << std::setfill('0') << std::hex
                          << value << " ";
            }
            std::cout << "\n";
        }
        std::cout << std::dec << std::setfill(' ');
    }

    std::vector<std::vector<std::byte>> Operations::sub_bytes(std::vector<std::vector<std::byte>>& state) {
        size_t rows = state.size(), columns = state[0].size();
        for (size_t i = 0; i < rows; ++i) {
            for (size_t j = 0; j < columns; ++j) {
                state[i][j] = Operations::SBOX[static_cast<size_t>(state[i][j])];
            }
        }
        return state;
    }

    std::vector<std::vector<std::byte>> Operations::inv_sub_bytes(std::vector<std::vector<std::byte>>& state) {
        size_t rows = state.size(), columns = state[0].size();
        for (size_t i = 0; i < rows; ++i) {
            for (size_t j = 0; j < columns; ++j) {
                state[i][j] = Operations::INV_SBOX[static_cast<size_t>(state[i][j])];
            }
        }
        return state;
    }

    std::vector<std::vector<std::byte>> Operations::shift_rows(std::vector<std::vector<std::byte>> &state) {
        size_t rows = state.size();
        for (size_t i = 0; i < rows; ++i) {
            if (i == 0)
                state[i] = bits_functions::cyclic_left_row_shift(state[i], 0);
            else if (i == 1)
                state[i] = bits_functions::cyclic_left_row_shift(state[i], 1);
            else if (i == 2) {
                if (block_size == 16 || block_size == 24)
                    state[i] = bits_functions::cyclic_left_row_shift(state[i], 2);
                else
                    state[i] = bits_functions::cyclic_left_row_shift(state[i], 3);
            }
            else {
                if (block_size == 24 || block_size == 32)
                    state[i] = bits_functions::cyclic_left_row_shift(state[i], 4);
                else
                    state[i] = bits_functions::cyclic_left_row_shift(state[i], 3);
            }
        }
        return state;
    }


    std::vector<std::vector<std::byte>> Operations::inv_shift_rows(std::vector<std::vector<std::byte>> &state) {
        size_t rows = state.size();
        for (size_t i = 0; i < rows; ++i) {
            if (i == 0)
                state[i] = bits_functions::cyclic_right_row_shift(state[i], 0);
            else if (i == 1)
                state[i] = bits_functions::cyclic_right_row_shift(state[i], 1);
            else if (i == 2) {
                if (block_size == 16 || block_size == 24)
                    state[i] = bits_functions::cyclic_right_row_shift(state[i], 2);
                else
                    state[i] = bits_functions::cyclic_right_row_shift(state[i], 3);
            }
            else {
                if (block_size == 24 || block_size == 32)
                    state[i] = bits_functions::cyclic_right_row_shift(state[i], 4);
                else
                    state[i] = bits_functions::cyclic_right_row_shift(state[i], 3);
            }
        }
        return state;
    }

    std::vector<std::vector<std::byte>> Operations::mix_columns(std::vector<std::vector<std::byte>> &state) {
        size_t rows = state.size(), columns = state[0].size();
        for (size_t i = 0; i < columns; i++) {
            std::vector<std::byte> b;

            for (size_t j = 0; j < rows; ++j) {
                b.push_back(state[j][i]);
            }

            std::vector<std::byte> d(rows, std::byte{0x00});
            for (size_t j = 0; j < rows; ++j) {
                for (size_t k = 0; k < rows; ++k) {
                    d[j] = galois_fields::GaloisField::add(
                            galois_fields::GaloisField::multiply(mix_colums_coefficients[j][k], b[k], mod),
                            d[j]);
                }
                state[j][i] = d[j];
            }
        }
        return state;
    }

    std::vector<std::vector<std::byte>> Operations::inv_mix_columns(std::vector<std::vector<std::byte>> &state) {
        size_t rows = state.size(), columns = state[0].size();
        for (size_t i = 0; i < columns; i++) {
            std::vector<std::byte> d;

            for (size_t j = 0; j < rows; ++j) {
                d.push_back(state[j][i]);
            }

            std::vector<std::byte> b(rows, std::byte{0x00});
            for (size_t j = 0; j < rows; ++j) {
                for (size_t k = 0; k < rows; ++k) {
                    b[j] = galois_fields::GaloisField::add(
                            galois_fields::GaloisField::multiply(inv_mix_columns_coefficients[j][k], d[k], mod),
                            b[j]);
                }
                state[j][i] = b[j];
            }
        }
        return state;
    }

    std::vector<std::vector<std::byte>> Operations::add_round_key(std::vector<std::vector<std::byte>> &state,
                                                                  std::vector<std::byte> round_key) {

        size_t rows = state.size(), columns = state[0].size();
        for (size_t i = 0; i < columns; ++i) {
            for (size_t j = 0; j < rows; ++j) {
                state[j][i] = galois_fields::GaloisField::add(state[j][i], round_key[i * 4 + j]);
            }
        }
        return state;
    }

    std::vector<std::byte> Operations::sub_word(std::vector<std::byte> &word) {
        for (auto& byte: word) {
            byte = SBOX[static_cast<size_t>(byte)];
        }
        return word;
    }


    RijndaelRoundKeyGenerator::RijndaelRoundKeyGenerator(size_t block_size_, const std::byte& polynomial):
        block_size(block_size_), mod(polynomial)  {

        Rcon.reserve(20);
        Rcon.push_back(std::byte{0x01});

        for (int i = 1; i < 20; ++i) {
            Rcon.push_back(galois_fields::GaloisField::multiply(Rcon[i - 1], std::byte{2}, polynomial));
        }
    }

    std::vector<std::vector<std::byte>> RijndaelRoundKeyGenerator::key_extension(const std::vector<std::byte> &key, size_t rounds) {
        Operations operations(mod, block_size);

        size_t rows = 4;
        size_t Nb = block_size / rows, Nk = key.size() / rows, total_words = Nb * (rounds + 1);
        std::vector<std::vector<std::byte>> expanded_key(total_words, std::vector<std::byte>(rows));
        size_t i = 0;
        while (i < Nk) {
            for (size_t j = 0; j < rows; ++j) {
                expanded_key[i][j] = key[i * rows + j];
            }
            ++i;
        }

        i = Nk;
        while (i < total_words) {
            std::vector<std::byte> temp = expanded_key[i - 1];
            if (i % Nk == 0) {
                temp = bits_functions::rotation_word(temp);
                temp = bits_functions::xor_vectors(operations.sub_word(temp),
                                                   {Rcon[i / Nk - 1], std::byte{0x00}, std::byte{0x00}, std::byte{0x00}},
                                                   4);
            } else if (Nk > 6 && i % Nk == 4) {
                temp = operations.sub_word(temp);
            }
            for (size_t j = 0; j < rows; ++j) {
                expanded_key[i][j] = galois_fields::GaloisField::add(expanded_key[i - Nk][j], temp[j]);
            }
            ++i;
        }

        std::vector<std::vector<std::byte>> round_keys(rounds + 1);
        for (size_t r = 0; r <= rounds; ++r) {
            std::vector<std::byte> rk(Nb * 4);

            for (size_t w = 0; w < Nb; ++w) {
                for (size_t byte = 0; byte < 4; ++byte) {
                    rk[w * 4 + byte] = expanded_key[r * Nb + w][byte];
                }
            }
            round_keys[r] = rk;
        }

        return round_keys;
    }

    Rijndael::Rijndael(std::vector<std::byte> &key_, size_t block_size_, size_t index_):
        key(std::move(key_)), block_size(block_size_), mod(irreducible_polynomials[index_]) {

        if (!galois_fields::GaloisField::is_polynom_irreducible(mod))
            throw std::invalid_argument("Mod polynom is not irreducible.");

        if (key.size() == 16 && block_size == 16) {
            rounds = 10;
        } else if (key.size() == 24 || block_size == 24) {
            rounds = 12;
        } else if (key.size() == 32 || block_size == 32) {
            rounds = 14;
        } else {
            throw std::invalid_argument("Invalid key or block size.");
        }
        round_key_generator = std::make_shared<RijndaelRoundKeyGenerator>(block_size, mod);
        round_keys = round_key_generator->key_extension(key, rounds);
        operations = std::make_shared<Operations>(mod, block_size);
    }

    Rijndael::Rijndael(std::vector<std::byte> &key_, size_t block_size_, std::byte polynominal_):
        key(std::move(key_)), block_size(block_size_), mod(polynominal_) {

        if (!galois_fields::GaloisField::is_polynom_irreducible(polynominal_))
            throw std::invalid_argument("Mod polynom is not irreducible.");

        if (key.size() == 16 && block_size == 16) {
            rounds = 10;
        } else if (key.size() == 24 || block_size == 24) {
            rounds = 12;
        } else if (key.size() == 32 || block_size == 32) {
            rounds = 14;
        } else {
            throw std::invalid_argument("Invalid key or block size.");
        }

        round_key_generator = std::make_shared<RijndaelRoundKeyGenerator>(block_size, mod);
        round_keys = round_key_generator->key_extension(key, rounds);
        operations = std::make_shared<Operations>(mod, block_size);

    }

    void Rijndael::set_key(const std::vector<std::byte> &key_) {
        key = key_;

    }

    std::vector<std::byte> Rijndael::encrypt(const std::vector<std::byte> &block) {
        auto state = to_state(block);
        state = operations->add_round_key(state, round_keys[0]);

        for (size_t round = 1; round < round_keys.size() - 1; ++round) {
            state = operations->sub_bytes(state);
            state = operations->shift_rows(state);
            state = operations->mix_columns(state);
            state = operations->add_round_key(state, round_keys[round]);
        }

        state = operations->sub_bytes(state);
        state = operations->shift_rows(state);
        state = operations->add_round_key(state, round_keys.back());

        std::vector<std::byte> result;
        for (size_t i = 0; i < state[0].size(); ++i) {
            for (size_t j = 0; j < state.size(); ++j) {
                result.push_back(state[j][i]);
            }
        }

        return result;
    }

    std::vector<std::byte> Rijndael::decrypt(const std::vector<std::byte> &block) {
        auto state = to_state(block);

        state = operations->add_round_key(state, round_keys.back());
        state = operations->inv_shift_rows(state);
        state = operations->inv_sub_bytes(state);

        for (int round = round_keys.size() - 2; round > 0; --round) {
            state = operations->add_round_key(state, round_keys[round]);
            state = operations->inv_mix_columns(state);
            state = operations->inv_shift_rows(state);
            state = operations->inv_sub_bytes(state);
        }

        state = operations->add_round_key(state, round_keys[0]);

        std::vector<std::byte> result;
        for (size_t i = 0; i < state[0].size(); ++i) {
            for (size_t j = 0; j < state.size(); ++j) {
                result.push_back(state[j][i]);
            }
        }

        return result;
    }

    size_t Rijndael::get_block_size() {
        return block_size;
    }
}