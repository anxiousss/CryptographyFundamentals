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
            bool passed_wiener = boost::multiprecision::pow(d, 4) >= (n / 81);


            if (passed_fermat && passed_wiener) {
                std::cout << boost::multiprecision::msb(n) << std::endl;
                return std::make_pair(std::make_pair(e, n), std::make_pair(d, n));
            }
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

    std::future<void>
    RSA::encrypt(const std::filesystem::path &input_file, std::optional<std::filesystem::path> &output_file) {
        return std::async(std::launch::async, [this, input_file, output_file]() {
            std::lock_guard<std::mutex> lock(mutex);

            if (!std::filesystem::exists(input_file)) {
                throw std::runtime_error("Input file does not exist: " + input_file.string());
            }

            std::filesystem::path actual_output_path = output_file.value_or(
                    input_file.parent_path() / (input_file.stem().string() + "_encrypted" + input_file.extension().string()));

            std::filesystem::create_directories(actual_output_path.parent_path());

            ///
            std::cout << "File encrypted: " << input_file << " -> " << actual_output_path << std::endl;

        });
    }

    std::future<void>
    RSA::decrypt(const std::filesystem::path &input_file, std::optional<std::filesystem::path> &output_file) {
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
                    input_file.parent_path() / (stem + "_decrypted" + input_file.extension().string()));

            std::filesystem::create_directories(actual_output_path.parent_path());

            ///

            std::cout << "File decrypted: " << input_file << " -> " << actual_output_path << std::endl;

        });
    }


    boost::multiprecision::cpp_int  Wieners_attack(boost::multiprecision::cpp_int e, boost::multiprecision::cpp_int n) {
        auto fraction = number_functions::NumberTheoryFunctions::make_continued_fraction(e, n);
        size_t fraction_size = fraction.size();
        std::vector<boost::multiprecision::cpp_int> numerators = {0, 1};
        std::vector<boost::multiprecision::cpp_int> denominators {1, 0};

        size_t index = 2;
        while (numerators.back() != e && denominators.back() != n) {
            boost::multiprecision::cpp_int num = fraction[index - 2] * numerators[index - 1] + numerators[index - 2],
                                            denum = fraction[index - 2] * denominators[index - 1] + denominators[index - 2];
            numerators.push_back(num);
            denominators.push_back(denum);
            ++index;
        }

        numerators.erase(numerators.begin());numerators.erase(numerators.begin() + 1);
        denominators.erase(denominators.begin());denominators.erase(denominators.begin() + 1);

        for (size_t i = 0; i < fraction_size; ++i) {
            auto phi_n = (e * denominators[i] - 1) / numerators[i];
            boost::multiprecision::cpp_int b = n - phi_n + 1, c = n;
            auto D = boost::multiprecision::pow(b, 2) - 4 * c;
            boost::multiprecision::cpp_int p = (-b + boost::multiprecision::sqrt(D)) / 2,
                                            q = (-b - boost::multiprecision::sqrt(D)) / 2;

            if (p * q == n) {
                return denominators[i];
            }
        }
    }
}