#include "rsa.hpp"

namespace rsa {

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
                dist(0, (boost::multiprecision::cpp_int{1} << bit_length));

        boost::random::random_device rd;
        boost::multiprecision::cpp_int p, q;
        bool found = false;
        while (true) {
            while (true) {
                p = dist(rd);
                std::cout << p << std::endl;
                if (this->primality_test->is_prime(p, min_probability) >= min_probability) {
                    while (true) {
                        q = dist(rd);
                        if (this->primality_test->is_prime(q, min_probability) >= min_probability) {
                            found = true;
                            break;
                        }
                    }
                }
                if (found)
                    break;
            }

            boost::multiprecision::cpp_int n = p * q;
            boost::multiprecision::cpp_int phi_n = (p - 1) * (q - 1);

            if (number_functions::NumberTheoryFunctions::gcd(phi_n, e) != 1)
                continue;

            auto [_, d, __] =
                    number_functions::NumberTheoryFunctions::extended_gcd(e, phi_n);

            d = d % phi_n;
            if (d < 0) {
                d += phi_n;
            }

            // Проверка на атаку винера и атаку ферма.
            if (boost::multiprecision::abs(p - q) > (boost::multiprecision::cpp_int{1} << 512) &&
                boost::multiprecision::pow(d, 4) >= n / 81)
                return std::make_pair(std::make_pair(e, n), std::make_pair(d, n));
        }
    }

    RSA::RSA(TestTypes type, double probability, size_t bit_length) {
        rsa_key_generator = std::make_shared<RsaKeysGeneration>(type, probability, bit_length);
        auto [pub, priv] = rsa_key_generator->generate_keys();
        public_key = pub; private_key = priv;
    }

    std::future<std::vector<std::byte>> RSA::encrypt(const std::vector<std::byte> &data) {
        return std::async(std::launch::async, [this, data]() -> std::vector<std::byte> {
            std::lock_guard<std::mutex> lock(mutex);

            boost::multiprecision::cpp_int msg;
            boost::multiprecision::import_bits(msg, data.begin(), data.end(), 8, false);

            boost::multiprecision::cpp_int number_cipher_text =
                    number_functions::NumberTheoryFunctions::mod_exp(msg, public_key.first, public_key.second);

            std::vector<std::byte> byte_cipher_text;

            std::vector<unsigned char> temp_buffer;
            boost::multiprecision::export_bits(number_cipher_text,
                                               std::back_inserter(temp_buffer), 8, false);

                for (unsigned char c : temp_buffer) {
                byte_cipher_text.push_back(static_cast<std::byte>(c));
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
}