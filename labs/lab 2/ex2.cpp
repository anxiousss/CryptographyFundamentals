#include <iostream>
#include <vector>
#include <cassert>
#include <random>
#include <chrono>
#include <thread>
#include "rsa.hpp"

using namespace rsa;

class RSAByteVectorTest {
private:
    std::unique_ptr<RSA> rsa;
    std::random_device rd;
    std::uniform_int_distribution<int> byte_dist{0, 255};

public:
    RSAByteVectorTest() {
        // Используем меньший размер ключа для тестов и более низкую вероятность
        rsa = std::make_unique<RSA>(TestTypes::MilerRabinTest, 0.95, 256);
    }

    void runAllTests() {
        std::cout << "Running RSA Byte Vector Tests...\n";

        testEmptyVector();
        testSingleByte();
        testSmallData();

        std::cout << "All basic tests passed! ✓\n";
    }

private:
    void testEmptyVector() {
        std::cout << "Testing empty vector... ";
        std::vector<std::byte> empty_data;

        auto encrypted_future = rsa->encrypt(empty_data);
        auto encrypted = encrypted_future.get();

        auto decrypted_future = rsa->decrypt(encrypted);
        auto decrypted = decrypted_future.get();

        assert(empty_data.size() == decrypted.size());
        std::cout << "PASS\n";
    }

    void testSingleByte() {
        std::cout << "Testing single byte... ";
        std::vector<std::byte> single_byte = {std::byte{0x42}};

        auto encrypted_future = rsa->encrypt(single_byte);
        auto encrypted = encrypted_future.get();

        // Проверяем что что-то зашифровалось
        assert(!encrypted.empty());

        auto decrypted_future = rsa->decrypt(encrypted);
        auto decrypted = decrypted_future.get();

        assert(single_byte == decrypted);
        std::cout << "PASS\n";
    }

    void testSmallData() {
        std::cout << "Testing small data... ";

        // Простые тестовые данные
        std::vector<std::byte> test_data = {
                std::byte{0x48}, std::byte{0x65}, std::byte{0x6C}, std::byte{0x6C}, std::byte{0x6F}  // "Hello"
        };

        auto encrypted_future = rsa->encrypt(test_data);
        auto encrypted = encrypted_future.get();

        assert(!encrypted.empty());

        auto decrypted_future = rsa->decrypt(encrypted);
        auto decrypted = decrypted_future.get();

        assert(test_data == decrypted);
        std::cout << "PASS\n";
    }
};

// Минимальный тест для отладки
void minimalTest() {
    std::cout << "=== Minimal Test ===\n";

    try {
        std::cout << "Step 1: Creating RSA instance with small parameters...\n";

        // Используем самые минимальные параметры
        auto rsa = std::make_unique<RSA>(TestTypes::MilerRabinTest, 0.9, 16);

        std::cout << "Step 2: RSA instance created successfully!\n";

        // Очень простой тест
        std::vector<std::byte> test_data = {std::byte{0x41}};
        std::cout << "Step 3: Testing with single byte...\n";

        auto encrypted_future = rsa->encrypt(test_data);
        std::cout << "Step 4: Encryption future obtained, waiting...\n";
        auto encrypted = encrypted_future.get();
        std::cout << "Step 5: Encryption completed. Encrypted size: " << encrypted.size() << "\n";

        auto decrypted_future = rsa->decrypt(encrypted);
        std::cout << "Step 6: Decryption future obtained, waiting...\n";
        auto decrypted = decrypted_future.get();
        std::cout << "Step 7: Decryption completed. Decrypted size: " << decrypted.size() << "\n";

        if (test_data == decrypted) {
            std::cout << "SUCCESS: Data encrypted and decrypted correctly!\n";
        } else {
            std::cout << "FAIL: Data mismatch after decryption\n";
        }

    } catch (const std::exception& e) {
        std::cerr << "Exception in minimalTest: " << e.what() << std::endl;
    } catch (...) {
        std::cerr << "Unknown exception in minimalTest" << std::endl;
    }
}

int main() {
    std::cout << "=== RSA Byte Vector Tests ===\n";

    try {
        // Сначала запустим минимальный тест
        minimalTest();

        // Затем базовые тесты
        std::cout << "\n=== Running Basic Test Suite ===\n";
        RSAByteVectorTest tester;
        tester.runAllTests();

        std::cout << "\n=== All tests completed successfully! ===\n";
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Test failed with unknown exception" << std::endl;
        return 1;
    }
}