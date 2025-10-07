#include <vector>
#include <bitset>


class RoundKeyGeneration {
public:
    virtual std::vector<std::vector<std::byte>> key_extension(const std::vector<std::byte>& key) = 0;
};

class EncryptionTransformation {
    virtual std::vector<std::byte> encrypt(const std::vector<std::byte>& block,
                                           const std::vector<std::byte>& key) = 0;
};

class SymmetricEncryption {
    virtual void encryption(const std::vector<std::byte>& block) = 0;
};