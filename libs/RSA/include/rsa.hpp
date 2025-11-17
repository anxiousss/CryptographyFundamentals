#include <memory>
#include <future>
#include <filesystem>
#include <optional>

#include "primality_tests.hpp"

namespace rsa {

    enum class TestTypes {
        FermaTest,
        SolovayStrassenTest,
        MilerRabinTest
    };

    class RsaKeysGeneration {
    private:
        const boost::multiprecision::cpp_int e = 65537;
        size_t bit_length;
        double min_probability;
        std::shared_ptr<primality_tests::PrimalityTest> primality_test;
    public:
        RsaKeysGeneration(TestTypes type, double probability, size_t bit_length);
        std::pair<std::pair<boost::multiprecision::cpp_int, boost::multiprecision::cpp_int>,
                std::pair<boost::multiprecision::cpp_int, boost::multiprecision::cpp_int>> generate_keys();
    };

    class RSA {
    private:
        mutable std::mutex mutex;
        std::shared_ptr<RsaKeysGeneration> rsa_key_generator;
        std::pair<boost::multiprecision::cpp_int, boost::multiprecision::cpp_int> public_key;
        std::pair<boost::multiprecision::cpp_int, boost::multiprecision::cpp_int> private_key;

    public:
        RSA(TestTypes type, double probability, size_t bit_length);
        std::future<std::vector<std::byte>> encrypt(const std::vector<std::byte>& data);
        std::future<void> encrypt(const std::filesystem::path& input_file,
                                  std::optional<std::filesystem::path>& output_file);

        std::future<std::vector<std::byte>> decrypt(const std::vector<std::byte>& data);
        std::future<void> decrypt(const std::filesystem::path& input_file,
                                  std::optional<std::filesystem::path>& output_file);
    };

    boost::multiprecision::cpp_int  Wieners_attack(boost::multiprecision::cpp_int e, boost::multiprecision::cpp_int n);
}