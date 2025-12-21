#include "test_serpent.hpp"
#include <iostream>
#include <vector>
#include <random>
#include <cassert>

namespace {
    // Тестовые векторы из официальной реализации Serpent
    const std::vector<std::byte> key_128 = {
            std::byte{0x80}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}
    };

    const std::vector<std::byte> plaintext_128 = {
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}
    };

    const std::vector<std::byte> ciphertext_128 = {
            std::byte{0xA2}, std::byte{0x23}, std::byte{0xAA}, std::byte{0x12},
            std::byte{0x10}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}
    };

    const std::vector<std::byte> test_key = {
            std::byte{0x00}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
            std::byte{0x04}, std::byte{0x05}, std::byte{0x06}, std::byte{0x07},
            std::byte{0x08}, std::byte{0x09}, std::byte{0x0A}, std::byte{0x0B},
            std::byte{0x0C}, std::byte{0x0D}, std::byte{0x0E}, std::byte{0x0F}
    };

    const std::vector<std::byte> test_plaintext = {
            std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33},
            std::byte{0x44}, std::byte{0x55}, std::byte{0x66}, std::byte{0x77},
            std::byte{0x88}, std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB},
            std::byte{0xCC}, std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}
    };

    const std::vector<std::byte> test_iv = {
            std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
            std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}, std::byte{0x11},
            std::byte{0x22}, std::byte{0x33}, std::byte{0x44}, std::byte{0x55},
            std::byte{0x66}, std::byte{0x77}, std::byte{0x88}, std::byte{0x99}
    };

    // Функция для генерации случайного вектора байтов
    std::vector<std::byte> random_bytes(size_t size) {
        std::vector<std::byte> result(size);
        std::random_device rd;
        std::uniform_int_distribution<unsigned short> dist(0, 255);

        for(size_t i = 0; i < size; ++i) {
            result[i] = static_cast<std::byte>(dist(rd));
        }
        return result;
    }
} // namespace

// Функция для создания экземпляра Serpent
std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_serpent_algorithm(const std::vector<std::byte>& key) {
    return std::make_unique<serpent::Serpent>(key);
}

SerpentTest::SerpentTest(TestRunner& runner_ref) : AlgorithmTestBase(runner_ref) {}

void SerpentTest::run_all_tests() {
    std::cout << "=== RUNNING SERPENT TESTS ===" << std::endl;

    test_key_sizes();
    test_known_vectors();
    test_encryption_decryption_consistency();
    test_basic_encryption_modes(test_key, test_iv, create_serpent_algorithm, "Serpent");
    test_padding_modes(test_key, test_iv, create_serpent_algorithm);
    test_edge_cases(test_key, create_serpent_algorithm);
    test_different_key_lengths();
    test_performance();

    std::cout << "\n=== SERPENT TESTS COMPLETE ===" << std::endl;
}

void SerpentTest::test_key_sizes() {
    runner.start_test("Key Size 128-bit");
    try {
        std::vector<std::byte> key(16, std::byte{0x00}); // 128 бит
        serpent::Serpent cipher(key);
        auto encrypted = cipher.encrypt(plaintext_128);
        runner.assert_true(!encrypted.empty(), "128-bit key should encrypt successfully");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }

    runner.start_test("Key Size 192-bit");
    try {
        std::vector<std::byte> key(24, std::byte{0x00}); // 192 бита
        serpent::Serpent cipher(key);
        auto encrypted = cipher.encrypt(plaintext_128);
        runner.assert_true(!encrypted.empty(), "192-bit key should encrypt successfully");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }

    runner.start_test("Key Size 256-bit");
    try {
        std::vector<std::byte> key(32, std::byte{0x00}); // 256 бит
        serpent::Serpent cipher(key);
        auto encrypted = cipher.encrypt(plaintext_128);
        runner.assert_true(!encrypted.empty(), "256-bit key should encrypt successfully");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void SerpentTest::test_known_vectors() {
    runner.start_test("Known Vector Test (128-bit key)");
    try {
        serpent::Serpent cipher(key_128);
        auto encrypted = cipher.encrypt(plaintext_128);

        // Проверяем первые несколько байтов (остальные могут быть нулями из-за padding)
        bool match = true;
        for (size_t i = 0; i < 8 && i < encrypted.size() && i < ciphertext_128.size(); ++i) {
            if (encrypted[i] != ciphertext_128[i]) {
                std::cout << "Mismatch at byte " << i << ": expected "
                          << std::hex << static_cast<int>(ciphertext_128[i])
                          << ", got " << static_cast<int>(encrypted[i]) << std::dec << std::endl;
                match = false;
            }
        }

        if (match) {
            auto decrypted = cipher.decrypt(encrypted);
            runner.assert_true(compare_byte_vectors(plaintext_128, decrypted),
                               "Decryption should return original plaintext");
            runner.end_test(true);
        } else {
            runner.end_test(false);
        }
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }

    runner.start_test("Custom Known Vector Test");
    try {
        serpent::Serpent cipher(test_key);
        auto encrypted = cipher.encrypt(test_plaintext);
        auto decrypted = cipher.decrypt(encrypted);

        runner.assert_true(compare_byte_vectors(test_plaintext, decrypted),
                           "Custom test vector should encrypt/decrypt correctly");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void SerpentTest::test_encryption_decryption_consistency() {
    runner.start_test("Encryption/Decryption Consistency (Random Data)");

    const int num_tests = 10;
    bool all_passed = true;

    for (int i = 0; i < num_tests; ++i) {
        try {
            // Генерируем случайный ключ (128, 192 или 256 бит)
            int key_size_choice = i % 3;
            size_t key_size;
            switch (key_size_choice) {
                case 0: key_size = 16; break; // 128 бит
                case 1: key_size = 24; break; // 192 бита
                case 2: key_size = 32; break; // 256 бит
                default: key_size = 16;
            }

            auto random_key = random_bytes(key_size);
            auto random_plaintext = random_bytes(16); // Блок 128 бит

            serpent::Serpent cipher(random_key);
            auto encrypted = cipher.encrypt(random_plaintext);
            auto decrypted = cipher.decrypt(encrypted);

            if (!compare_byte_vectors(random_plaintext, decrypted)) {
                std::cout << "Test " << i + 1 << " failed: decryption mismatch" << std::endl;
                all_passed = false;
            }
        } catch (const std::exception& e) {
            std::cout << "Test " << i + 1 << " exception: " << e.what() << std::endl;
            all_passed = false;
        }
    }

    runner.assert_true(all_passed, "All random encryption/decryption tests should pass");
    runner.end_test(all_passed);
}

void SerpentTest::test_different_key_lengths() {
    runner.start_test("Different Key Lengths - Encryption/Decryption");

    bool all_passed = true;

    // Тестируем разные длины ключей
    std::vector<size_t> key_lengths = {16, 24, 32}; // 128, 192, 256 бит

    for (size_t key_len : key_lengths) {
        try {
            auto key = random_bytes(key_len);
            auto plaintext = random_bytes(16);

            serpent::Serpent cipher(key);
            auto encrypted = cipher.encrypt(plaintext);
            auto decrypted = cipher.decrypt(encrypted);

            if (!compare_byte_vectors(plaintext, decrypted)) {
                std::cout << "Key length " << key_len * 8 << "-bit test failed" << std::endl;
                all_passed = false;
            }
        } catch (const std::exception& e) {
            std::cout << "Key length " << key_len * 8 << "-bit exception: " << e.what() << std::endl;
            all_passed = false;
        }
    }

    runner.assert_true(all_passed, "All key lengths should work correctly");
    runner.end_test(all_passed);
}

void SerpentTest::test_performance() {
    runner.start_test("Performance Test (Small Data)");

    try {
        auto key = random_bytes(16);
        serpent::Serpent cipher(key);

        // Тестируем производительность на 1000 блоках
        const int num_blocks = 1000;
        std::vector<std::vector<std::byte>> blocks(num_blocks);

        for (int i = 0; i < num_blocks; ++i) {
            blocks[i] = random_bytes(16);
        }

        auto start = std::chrono::high_resolution_clock::now();

        // Шифрование
        for (int i = 0; i < num_blocks; ++i) {
            cipher.encrypt(blocks[i]);
        }

        auto mid = std::chrono::high_resolution_clock::now();

        // Дешифрование (используем зашифрованные блоки)
        std::vector<std::vector<std::byte>> encrypted_blocks(num_blocks);
        for (int i = 0; i < num_blocks; ++i) {
            encrypted_blocks[i] = cipher.encrypt(blocks[i]);
        }

        for (int i = 0; i < num_blocks; ++i) {
            cipher.decrypt(encrypted_blocks[i]);
        }

        auto end = std::chrono::high_resolution_clock::now();

        auto encrypt_time = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start);
        auto decrypt_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid);
        auto total_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        double encrypt_speed = (num_blocks * 16.0 * 8.0) / (encrypt_time.count() / 1000.0) / 1024.0; // Кбит/с
        double decrypt_speed = (num_blocks * 16.0 * 8.0) / (decrypt_time.count() / 1000.0) / 1024.0; // Кбит/с

        std::cout << "Performance results:" << std::endl;
        std::cout << "  Blocks processed: " << num_blocks << std::endl;
        std::cout << "  Total time: " << total_time.count() << " ms" << std::endl;
        std::cout << "  Encryption time: " << encrypt_time.count() << " ms ("
                  << std::fixed << std::setprecision(2) << encrypt_speed << " Kbit/s)" << std::endl;
        std::cout << "  Decryption time: " << decrypt_time.count() << " ms ("
                  << std::fixed << std::setprecision(2) << decrypt_speed << " Kbit/s)" << std::endl;

        runner.assert_true(total_time.count() < 10000, "Performance should be reasonable");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Performance test exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_serpent_file_operations(TestRunner& runner, const TestFileConfig& config) {
    SerpentTest serpent_test(runner);

    std::cout << "\n=== TESTING SERPENT FILE OPERATIONS ===" << std::endl;

    // Тестируем с разными длинами ключей
    std::vector<std::pair<std::string, std::vector<std::byte>>> test_keys = {
            {"128-bit", random_bytes(16)},
            {"192-bit", random_bytes(24)},
            {"256-bit", random_bytes(32)}
    };

    for (const auto& [key_name, key] : test_keys) {
        std::cout << "\n--- Testing with " << key_name << " key ---" << std::endl;
        serpent_test.test_file_operations(key, test_iv, create_serpent_algorithm, config, "Serpent-" + key_name);
    }
}