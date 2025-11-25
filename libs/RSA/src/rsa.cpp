#include "rsa.hpp"
#include <openssl/sha.h>


namespace rsa {


    OAEP::OAEP(size_t hlen_): hlen(hlen_) {}

    std::vector<std::byte> OAEP::hash(const std::vector<std::byte> &data) {
        std::vector<std::byte> hash_result(hlen);

        switch (hlen) {
            case 20:
                SHA1(reinterpret_cast<const unsigned char*>(data.data()),
                     data.size(),
                     reinterpret_cast<unsigned char*>(hash_result.data()));
                break;

            case 28:
                SHA224(reinterpret_cast<const unsigned char*>(data.data()),
                       data.size(),
                       reinterpret_cast<unsigned char*>(hash_result.data()));
                break;

            case 32:
                SHA256(reinterpret_cast<const unsigned char*>(data.data()),
                       data.size(),
                       reinterpret_cast<unsigned char*>(hash_result.data()));
                break;

            case 48:
                SHA384(reinterpret_cast<const unsigned char*>(data.data()),
                       data.size(),
                       reinterpret_cast<unsigned char*>(hash_result.data()));
                break;

            case 64:
                SHA512(reinterpret_cast<const unsigned char*>(data.data()),
                       data.size(),
                       reinterpret_cast<unsigned char*>(hash_result.data()));
                break;

            default:
                throw std::invalid_argument("Unsupported hash length: " + std::to_string(hlen) +
                                            ". Supported lengths: 20 (SHA1), 28 (SHA224), 32 (SHA256), 48 (SHA384), 64 (SHA512)");
        }

        return hash_result;
    }
    std::vector<std::byte> OAEP::mgf1(const std::vector<std::byte>& seed, size_t length) {
        if (length > (1ULL << 32) * hlen) {
            throw std::invalid_argument("mask too long");
        }

        std::vector<std::byte> T;
        for (uint32_t i = 0; i <= (length - 1) / hlen; i++) {
            std::vector<std::byte> data = seed;
            auto counter_bytes = bits_functions::I2OSP(i, 4);

            data.insert(data.end(), counter_bytes.begin(), counter_bytes.end());

            auto hash_result = hash(data);
            T.insert(T.end(), hash_result.begin(), hash_result.end());
        }

        return std::vector<std::byte>(T.begin(), T.begin() + length);
    }

    std::vector<std::byte>
    OAEP::encode(const std::vector<std::byte> &msg, size_t k, const std::vector<std::byte> &label) {
        if (msg.size() > k - 2 * hlen - 2) {
            throw std::runtime_error("Message too long for OAEP padding.");
        }

        std::vector<std::byte> lhash = hash(label);
        size_t ps_len = k - msg.size() - 2 * hlen - 2;
        std::vector<std::byte> PS{ps_len, std::byte{0x00}};
        PS.push_back(std::byte{0x01});

        std::vector<std::byte> DB = bits_functions::concat_vectors<std::byte>(lhash, PS, msg);

        std::vector<std::byte> seed = bits_functions::random_bytes_vector(hlen);
        std::vector<std::byte> db_mask = mgf1(seed, k - hlen - 1);
        std::vector<std::byte> masked_db = bits_functions::xor_vectors(DB, db_mask, k - hlen - 1);

        std::vector<std::byte> seed_mask = mgf1(masked_db, hlen);
        std::vector<std::byte> masked_seed = bits_functions::xor_vectors(seed, seed_mask, hlen);

        masked_seed.insert(masked_seed.begin(), std::byte{0x00});

        std::vector<std::byte> EM = bits_functions::concat_vectors<std::byte>(masked_seed, masked_db);
        return EM;
    }

    std::vector<std::byte> OAEP::decode(const std::vector<std::byte>& encoded_msg, size_t k,
                                        const std::vector<std::byte>& label) {
        if (encoded_msg.size() != k) {
            throw std::runtime_error("Invalid message size for decoding. Expected: " +
                                     std::to_string(k) + ", got: " +
                                     std::to_string(encoded_msg.size()));
        }

        if (encoded_msg[0] != std::byte{0x00}) {
            throw std::runtime_error("Invalid message for decoding - first byte is not zero");
        }

        auto parts = bits_functions::split_vector_accumulate(encoded_msg,
                                                             {1, hlen, k - hlen - 1});
        std::vector<std::byte>& masked_seed = parts[1];
        std::vector<std::byte>& masked_db = parts[2];

        std::vector<std::byte> seed_mask = mgf1(masked_db, hlen);
        std::vector<std::byte> seed = bits_functions::xor_vectors(masked_seed, seed_mask, hlen);

        std::vector<std::byte> db_mask = mgf1(seed, k - hlen - 1);
        std::vector<std::byte> DB = bits_functions::xor_vectors(masked_db, db_mask, k - hlen - 1);

        auto db_parts = bits_functions::split_vector_accumulate(DB, {hlen, DB.size() - hlen});
        std::vector<std::byte>& lhash_received = db_parts[0];
        std::vector<std::byte>& rest = db_parts[1];

        auto separator_pos = std::find(rest.begin(), rest.end(), std::byte{0x01});
        if (separator_pos == rest.end()) {
            throw std::runtime_error("Separator 0x01 not found in DB");
        }

        std::vector<std::byte> PS(rest.begin(), separator_pos);
        std::vector<std::byte> message(separator_pos + 1, rest.end());

        std::vector<std::byte> lhash_computed = hash(label);
        if (lhash_received != lhash_computed) {
            throw std::runtime_error("Label hashes do not match.");
        }

        if (!std::all_of(PS.begin(), PS.end(), [](std::byte b) { return b == std::byte{0x00}; })) {
            throw std::runtime_error("PS contains non-zero bytes.");
        }

        return message;
    }

    RsaKeysGeneration::RsaKeysGeneration(TestTypes type_, double probability_, size_t bit_length_):
            min_probability(probability_), bit_length(bit_length_) {
        switch (type_) {
            case TestTypes::FermaTest:
                this->primality_test = std::make_shared<primality_tests::FermatPrimalityTest>();
                break;
            case TestTypes::SolovayStrassenTest:
                this->primality_test = std::make_shared<primality_tests::SolovayStrassenPrimalityTest>();
                break;
            case TestTypes::MilerRabinTest:
                this->primality_test = std::make_shared<primality_tests::MillerRabinPrimalityTest>();
                break;
        }
    }

    std::pair<std::pair<boost::multiprecision::cpp_int, boost::multiprecision::cpp_int>,
            std::pair<boost::multiprecision::cpp_int, boost::multiprecision::cpp_int>>
    RsaKeysGeneration::generate_keys() {
        boost::random::uniform_int_distribution<boost::multiprecision::cpp_int>
                dist(boost::multiprecision::cpp_int(1) << (bit_length - 1),
                     (boost::multiprecision::cpp_int(1) << bit_length) - 1);

        boost::random::random_device rd;

        while (true) {
            boost::multiprecision::cpp_int p;
            do {
                p = dist(rd);
            } while (this->primality_test->is_prime(p, min_probability) < min_probability);

            boost::multiprecision::cpp_int q;
            do {
                q = dist(rd);
            } while (this->primality_test->is_prime(q, min_probability) < min_probability || q == p);

            boost::multiprecision::cpp_int n = p * q;
            boost::multiprecision::cpp_int phi_n = (p - 1) * (q - 1);


            if (number_functions::NumberTheoryFunctions::gcd(phi_n, e) != 1) {
                continue;
            }

            auto [gcd_val, d, y] = number_functions::NumberTheoryFunctions::extended_gcd(e, phi_n);
            d = d % phi_n;
            if (d < 0) {
                d += phi_n;
            }


            bool passed_fermat = boost::multiprecision::abs(p - q) > (boost::multiprecision::cpp_int{1} << (bit_length / 2 - 1));
            bool passed_wiener = boost::multiprecision::pow(d, 4) > (n / 81);


            if (passed_fermat && passed_wiener) {
                return std::make_pair(std::make_pair(e, n), std::make_pair(d, n));
            }
        }
    }

    std::pair<std::pair<boost::multiprecision::cpp_int, boost::multiprecision::cpp_int>,
            std::pair<boost::multiprecision::cpp_int, boost::multiprecision::cpp_int>>
    RsaKeysGeneration::generate_bad_keys() {
        boost::random::uniform_int_distribution<boost::multiprecision::cpp_int>
                dist(boost::multiprecision::cpp_int(1) << (bit_length - 1),
                     (boost::multiprecision::cpp_int(1) << bit_length) - 1);

        boost::random::random_device rd;

        while (true) {
            boost::multiprecision::cpp_int p;
            do {
                p = dist(rd);
            } while (this->primality_test->is_prime(p, min_probability) < min_probability);

            boost::multiprecision::cpp_int q;
            do {
                q = dist(rd);
            } while (this->primality_test->is_prime(q, min_probability) < min_probability || q == p);

            boost::multiprecision::cpp_int n = p * q;
            boost::multiprecision::cpp_int phi_n = (p - 1) * (q - 1);


            if (number_functions::NumberTheoryFunctions::gcd(phi_n, e) != 1) {
                continue;
            }

            auto [gcd_val, d, y] = number_functions::NumberTheoryFunctions::extended_gcd(e, phi_n);
            d = d % phi_n;
            if (d < 0) {
                d += phi_n;
            }

            return std::make_pair(std::make_pair(e, n), std::make_pair(d, n));
        }
    }

    RSA::RSA(TestTypes type, double probability, size_t bit_length, bool vulnerability) {
        rsa_key_generator = std::make_shared<RsaKeysGeneration>(type, probability, bit_length);
        std::pair<std::pair<boost::multiprecision::cpp_int, boost::multiprecision::cpp_int>,
                std::pair<boost::multiprecision::cpp_int, boost::multiprecision::cpp_int>> res;
        if (vulnerability) {
            res = rsa_key_generator->generate_bad_keys();
        } else {
            res = rsa_key_generator->generate_keys();
        }
        auto [pub, priv] = res;
        public_key = pub; private_key = priv;
    }

    std::future<std::vector<std::byte>> RSA::encrypt(const std::vector<std::byte> &data) {
        return std::async(std::launch::async, [this, data]() -> std::vector<std::byte> {
            std::lock_guard<std::mutex> lock(mutex);

            size_t modulus_bytes = (boost::multiprecision::msb(public_key.second) + 7) / 8;

            boost::multiprecision::cpp_int msg;
            boost::multiprecision::import_bits(msg, data.begin(), data.end(), 8, false);

            if (msg >= public_key.second) {
                throw std::runtime_error("Message too large for modulus");
            }

            boost::multiprecision::cpp_int number_cipher_text =
                    number_functions::NumberTheoryFunctions::mod_exp(msg, public_key.first, public_key.second);

            std::vector<std::byte> byte_cipher_text(modulus_bytes, std::byte{0});
            std::vector<unsigned char> temp_buffer;
            boost::multiprecision::export_bits(number_cipher_text,
                                               std::back_inserter(temp_buffer), 8, false);

            size_t offset = modulus_bytes - temp_buffer.size();
            for (size_t i = 0; i < temp_buffer.size(); ++i) {
                byte_cipher_text[offset + i] = static_cast<std::byte>(temp_buffer[i]);
            }

            return byte_cipher_text;
        });
    }

    std::future<std::vector<std::byte>> RSA::decrypt(const std::vector<std::byte> &cipher_data) {
        return std::async(std::launch::async, [this, cipher_data]() -> std::vector<std::byte> {
            std::lock_guard<std::mutex> lock(mutex);

            boost::multiprecision::cpp_int cipher_msg;

            std::vector<unsigned char> temp_buffer;
            for (std::byte b : cipher_data) {
                temp_buffer.push_back(static_cast<unsigned char>(b));
            }
            boost::multiprecision::import_bits(cipher_msg, temp_buffer.begin(), temp_buffer.end(), 8, false);

            boost::multiprecision::cpp_int number_plain_text =
                    number_functions::NumberTheoryFunctions::mod_exp(cipher_msg, private_key.first, private_key.second);

            std::vector<std::byte> byte_plain_text;
            std::vector<unsigned char> temp_buffer2;
            boost::multiprecision::export_bits(number_plain_text,
                                               std::back_inserter(temp_buffer2), 8, false);

            for (unsigned char c : temp_buffer2) {
                byte_plain_text.push_back(static_cast<std::byte>(c));
            }

            return byte_plain_text;
        });
    }


    std::future<void>
    RSA::encrypt(const std::filesystem::path &input_file,
                 std::optional<std::filesystem::path> &output_file) {
        return std::async(std::launch::async, [this, input_file, output_file]() {
            std::lock_guard<std::mutex> lock(mutex);

            if (!std::filesystem::exists(input_file)) {
                throw std::runtime_error("Input file does not exist: " + input_file.string());
            }

            std::filesystem::path actual_output_path = output_file.value_or(
                    input_file.parent_path() /
                    (input_file.stem().string() + "_encrypted" + input_file.extension().string())
            );

            std::filesystem::create_directories(actual_output_path.parent_path());

            std::ifstream in_file(input_file, std::ios::binary);
            std::ofstream out_file(actual_output_path, std::ios::binary);

            if (!in_file.is_open()) {
                throw std::runtime_error("Cannot open input file: " + input_file.string());
            }
            if (!out_file.is_open()) {
                throw std::runtime_error("Cannot create output file: " + actual_output_path.string());
            }

            size_t modulus_bits = boost::multiprecision::msb(public_key.second) + 1;
            size_t modulus_bytes = (modulus_bits + 7) / 8;

            OAEP oaep;

            size_t max_data_per_block = modulus_bytes - 2 * oaep.hlen - 2;
            if (max_data_per_block <= 0) {
                throw std::runtime_error("RSA key size too small for OAEP padding");
            }

            uint64_t original_file_size = std::filesystem::file_size(input_file);
            out_file.write(reinterpret_cast<const char*>(&original_file_size), sizeof(original_file_size));

            std::vector<char> buffer(max_data_per_block);
            uint64_t total_bytes_processed = 0;
            uint64_t total_blocks = 0;

            while (in_file.read(buffer.data(), max_data_per_block) || in_file.gcount() > 0) {
                size_t bytes_read = in_file.gcount();
                total_bytes_processed += bytes_read;

                std::vector<std::byte> data_block(bytes_read);
                for (size_t i = 0; i < bytes_read; ++i) {
                    data_block[i] = static_cast<std::byte>(buffer[i]);
                }

                try {
                    std::vector<std::byte> padded_data = oaep.encode(data_block, modulus_bytes, {});

                    boost::multiprecision::cpp_int msg_int(0);
                    for (size_t i = 0; i < padded_data.size(); ++i) {
                        msg_int <<= 8;
                        msg_int += static_cast<unsigned char>(padded_data[i]);
                    }

                    if (msg_int >= public_key.second) {
                        throw std::runtime_error("Padded message too large for modulus");
                    }

                    boost::multiprecision::cpp_int encrypted_int =
                            number_functions::NumberTheoryFunctions::mod_exp(msg_int, public_key.first, public_key.second);

                    std::vector<std::byte> encrypted_bytes(modulus_bytes, std::byte{0});

                    std::vector<unsigned char> temp_buffer;
                    boost::multiprecision::export_bits(encrypted_int,
                                                       std::back_inserter(temp_buffer), 8);

                    size_t start_pos = modulus_bytes - temp_buffer.size();
                    for (size_t i = 0; i < temp_buffer.size(); ++i) {
                        encrypted_bytes[start_pos + i] = static_cast<std::byte>(temp_buffer[i]);
                    }

                    out_file.write(reinterpret_cast<const char*>(encrypted_bytes.data()),
                                   encrypted_bytes.size());

                    total_blocks++;

                } catch (const std::exception& e) {
                    throw std::runtime_error("Encryption error at block " +
                                             std::to_string(total_blocks) + ": " + e.what());
                }
            }

            in_file.close();
            out_file.close();

            std::cout << "File encrypted successfully: " << input_file
                      << " -> " << actual_output_path
                      << " (" << total_blocks << " blocks, " << total_bytes_processed << " bytes processed)" << std::endl;
        });
    }

    std::future<void>
    RSA::decrypt(const std::filesystem::path &input_file,
                 std::optional<std::filesystem::path> &output_file) {
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
                    input_file.parent_path() /
                    (stem + "_decrypted" + input_file.extension().string())
            );

            std::filesystem::create_directories(actual_output_path.parent_path());

            std::ifstream in_file(input_file, std::ios::binary);
            std::ofstream out_file(actual_output_path, std::ios::binary);

            if (!in_file.is_open()) {
                throw std::runtime_error("Cannot open input file: " + input_file.string());
            }
            if (!out_file.is_open()) {
                throw std::runtime_error("Cannot create output file: " + actual_output_path.string());
            }

            uint64_t original_file_size;
            in_file.read(reinterpret_cast<char*>(&original_file_size), sizeof(original_file_size));
            if (in_file.gcount() != sizeof(original_file_size)) {
                throw std::runtime_error("Cannot read original file size from encrypted file");
            }

            size_t modulus_bits = boost::multiprecision::msb(private_key.second) + 1;
            size_t modulus_bytes = (modulus_bits + 7) / 8;

            OAEP oaep;
            uint64_t total_blocks = 0;
            uint64_t total_bytes_recovered = 0;


            std::vector<char> buffer(modulus_bytes);

            while (in_file.read(buffer.data(), modulus_bytes)) {
                total_blocks++;

                try {
                    std::vector<std::byte> encrypted_block(modulus_bytes);
                    for (size_t i = 0; i < modulus_bytes; ++i) {
                        encrypted_block[i] = static_cast<std::byte>(buffer[i]);
                    }

                    boost::multiprecision::cpp_int encrypted_int(0);
                    for (size_t i = 0; i < encrypted_block.size(); ++i) {
                        encrypted_int <<= 8;
                        encrypted_int += static_cast<unsigned char>(encrypted_block[i]);
                    }

                    boost::multiprecision::cpp_int decrypted_int =
                            number_functions::NumberTheoryFunctions::mod_exp(encrypted_int, private_key.first, private_key.second);

                    std::vector<std::byte> padded_data(modulus_bytes, std::byte{0});

                    std::vector<unsigned char> temp_buffer;
                    boost::multiprecision::export_bits(decrypted_int,
                                                       std::back_inserter(temp_buffer), 8);

                    size_t start_pos = modulus_bytes - temp_buffer.size();
                    for (size_t i = 0; i < temp_buffer.size(); ++i) {
                        padded_data[start_pos + i] = static_cast<std::byte>(temp_buffer[i]);
                    }

                    std::vector<std::byte> original_data = oaep.decode(padded_data, modulus_bytes, {});

                    size_t bytes_to_write = original_data.size();
                    if (total_bytes_recovered + bytes_to_write > original_file_size) {
                        bytes_to_write = original_file_size - total_bytes_recovered;
                    }

                    out_file.write(reinterpret_cast<const char*>(original_data.data()),
                                   bytes_to_write);
                    total_bytes_recovered += bytes_to_write;

                    if (total_bytes_recovered >= original_file_size) {
                        break;
                    }

                } catch (const std::exception& e) {
                    throw std::runtime_error("Decryption error at block " +
                                             std::to_string(total_blocks) + ": " + e.what());
                }
            }

            in_file.close();
            out_file.close();

            if (total_bytes_recovered != original_file_size) {
                throw std::runtime_error("File size mismatch after decryption. Expected: " +
                                         std::to_string(original_file_size) + ", got: " +
                                         std::to_string(total_bytes_recovered));
            }

            std::cout << "File decrypted successfully: " << input_file
                      << " -> " << actual_output_path
                      << " (" << total_blocks << " blocks, " << total_bytes_recovered << " bytes recovered)" << std::endl;
        });
    }

    boost::multiprecision::cpp_int Wieners_attack(
            boost::multiprecision::cpp_int e,
            boost::multiprecision::cpp_int n) {

        std::vector<boost::multiprecision::cpp_int> fraction =
                number_functions::NumberTheoryFunctions::make_continued_fraction(e, n);

        size_t fraction_size = fraction.size();

        std::vector<boost::multiprecision::cpp_int> numerators;
        std::vector<boost::multiprecision::cpp_int> denominators;

        numerators.push_back(0);
        numerators.push_back(1);
        denominators.push_back(1);
        denominators.push_back(0);

        for (size_t i = 0; i < fraction_size; ++i) {
            boost::multiprecision::cpp_int num =
                    fraction[i] * numerators[i + 1] + numerators[i];
            boost::multiprecision::cpp_int den =
                    fraction[i] * denominators[i + 1] + denominators[i];

            numerators.push_back(num);
            denominators.push_back(den);

            boost::multiprecision::cpp_int d = denominators.back();
            boost::multiprecision::cpp_int k = numerators.back();

            if (k == 0) continue;

            if ((e * d - 1) % k != 0) continue;

            boost::multiprecision::cpp_int phi_n = (e * d - 1) / k;

            boost::multiprecision::cpp_int b = n - phi_n + 1;
            boost::multiprecision::cpp_int discriminant = b * b - 4 * n;

            if (discriminant < 0) continue;

            boost::multiprecision::cpp_int root = boost::multiprecision::sqrt(discriminant);
            if (root * root != discriminant) continue;

            boost::multiprecision::cpp_int p = (b + root) / 2;
            boost::multiprecision::cpp_int q = (b - root) / 2;

            if (p * q == n) {
                return d;
            }
        }

        throw std::runtime_error("Wiener's attack failed: private key not found");
    }
}