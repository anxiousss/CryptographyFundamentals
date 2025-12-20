#include <vector>
#include <array>
#include <future>
#include <algorithm>
#include <iostream>
#include <filesystem>
#include <fstream>


namespace stream_cipher {

    class RC4 {
    private:
        std::array<size_t , 256> permutation;
        std::vector<std::byte> key;
        size_t k = 0, l = 0;
        void key_scheduling();
        std::byte PRGA();
        mutable std::mutex mutex;


    public:
        RC4(const std::vector<std::byte>& key_);
        std::future<std::vector<std::byte>> encrypt(const std::vector<std::byte>& data);
        std::future<void> encrypt(const std::filesystem::path& input_file,
                                  std::optional<std::filesystem::path>& output_file);

        std::future<std::vector<std::byte>> decrypt(const std::vector<std::byte>& data);
        std::future<void> decrypt(const std::filesystem::path& input_file,
                                  std::optional<std::filesystem::path>& output_file);

    };
}