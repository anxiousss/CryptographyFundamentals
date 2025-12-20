#include "bits_functions.hpp"
#include "rc4.hpp"

std::vector<std::byte> string_to_bytes(const std::string& s) {
    std::vector<std::byte> sb;
    for (const auto& c: s) {
        sb.push_back(static_cast<std::byte>(c));
    }
    return sb;
}

int main() {

    std::string key = "Key", plaintext = "Plaintext";
    std::vector<std::byte> byte_key = string_to_bytes(key),
            byte_plaintext = string_to_bytes(plaintext);
    stream_cipher::RC4 alg(byte_key);

    std::optional<std::filesystem::path> output_encrypt =
            "tests/test_rc4/SMILEFACE.bin";
    std::optional<std::filesystem::path> output_decrypt =
            "tests/test_rc4/SMILEFACE.jpg";

    std::filesystem::create_directories("tests/test_rc4");

    alg.encrypt("test_files/SMILEFACE.jpg", output_encrypt).get();

    alg.decrypt("tests/test_rc4/SMILEFACE.bin", output_decrypt).get();


    return 0;
}