#include "test_des.hpp"
#include <chrono>
#include <iomanip>

// Инициализация конфигурации тестов DES
namespace test_config_des {
    std::filesystem::path text_file_path = "";
    std::filesystem::path binary_file_path = "";
    std::filesystem::path image_file_path = "";
    std::filesystem::path pdf_file_path = "";
    std::filesystem::path zip_file_path = "";
    std::filesystem::path mp4_file_path = "";

    void set_custom_files(
            const std::filesystem::path& text_file,
            const std::filesystem::path& binary_file,
            const std::filesystem::path& image_file,
            const std::filesystem::path& pdf_file,
            const std::filesystem::path& zip_file,
            const std::filesystem::path& mp4_file
    ) {
        if (!text_file.empty()) text_file_path = text_file;
        if (!binary_file.empty()) binary_file_path = binary_file;
        if (!image_file.empty()) image_file_path = image_file;
        if (!pdf_file.empty()) pdf_file_path = pdf_file;
        if (!zip_file.empty()) zip_file_path = zip_file;
        if (!mp4_file.empty()) mp4_file_path = mp4_file;

        std::cout << "Custom DES files configuration:" << std::endl;
        if (!text_file_path.empty()) std::cout << "  Text: " << text_file_path << std::endl;
        if (!binary_file_path.empty()) std::cout << "  Binary: " << binary_file_path << std::endl;
        if (!image_file_path.empty()) std::cout << "  Image: " << image_file_path << std::endl;
        if (!pdf_file_path.empty()) std::cout << "  PDF: " << pdf_file_path << std::endl;
        if (!zip_file_path.empty()) std::cout << "  ZIP: " << zip_file_path << std::endl;
        if (!mp4_file_path.empty()) std::cout << "  MP4: " << mp4_file_path << std::endl;
    }
}

void TestRunner::start_test(const std::string& test_name) {
    current_test = test_name;
    std::cout << "TEST: " << test_name << " ";
}

void TestRunner::end_test(bool passed) {
    if (passed) {
        std::cout << "PASSED" << std::endl;
        tests_passed++;
    } else {
        std::cout << "FAILED" << std::endl;
        tests_failed++;
    }
}

void TestRunner::print_summary() {
    std::cout << "\n=== TEST SUMMARY ===" << std::endl;
    std::cout << "Passed: " << tests_passed << std::endl;
    std::cout << "Failed: " << tests_failed << std::endl;
    std::cout << "Total:  " << (tests_passed + tests_failed) << std::endl;

    if (tests_failed == 0) {
        std::cout << "ALL TESTS PASSED!" << std::endl;
    } else {
        std::cout << "SOME TESTS FAILED!" << std::endl;
    }
}

bool compare_byte_vectors(const std::vector<std::byte>& v1, const std::vector<std::byte>& v2) {
    if (v1.size() != v2.size()) {
        std::cout << "Size mismatch: " << v1.size() << " vs " << v2.size() << std::endl;
        return false;
    }
    for (size_t i = 0; i < v1.size(); ++i) {
        if (v1[i] != v2[i]) {
            std::cout << "Byte mismatch at position " << i << std::endl;
            return false;
        }
    }
    return true;
}

bool compare_files(const std::filesystem::path& file1, const std::filesystem::path& file2) {
    if (!std::filesystem::exists(file1) || !std::filesystem::exists(file2)) {
        return false;
    }

    if (std::filesystem::file_size(file1) != std::filesystem::file_size(file2)) {
        return false;
    }

    std::ifstream f1(file1, std::ios::binary);
    std::ifstream f2(file2, std::ios::binary);

    if (!f1.is_open() || !f2.is_open()) {
        return false;
    }

    char ch1, ch2;
    while (f1.get(ch1) && f2.get(ch2)) {
        if (ch1 != ch2) {
            return false;
        }
    }

    return true;
}

void print_file_metrics(const std::string& description,
                        uint64_t original_size,
                        uint64_t encrypted_size,
                        uint64_t decrypted_size,
                        const std::chrono::milliseconds& encrypt_time,
                        const std::chrono::milliseconds& decrypt_time) {
    std::cout << "\n=== " << description << " Metrics ===" << std::endl;
    std::cout << "Original size: " << original_size << " bytes ("
              << std::fixed << std::setprecision(2) << (original_size / 1024.0 / 1024.0) << " MB)" << std::endl;
    std::cout << "Encrypted size: " << encrypted_size << " bytes ("
              << std::fixed << std::setprecision(2) << (encrypted_size / 1024.0 / 1024.0) << " MB)" << std::endl;
    std::cout << "Decrypted size: " << decrypted_size << " bytes ("
              << std::fixed << std::setprecision(2) << (decrypted_size / 1024.0 / 1024.0) << " MB)" << std::endl;
    std::cout << "Encryption time: " << encrypt_time.count() << " ms" << std::endl;
    std::cout << "Decryption time: " << decrypt_time.count() << " ms" << std::endl;
    std::cout << "Encryption throughput: "
              << std::fixed << std::setprecision(2)
              << (original_size / 1024.0 / 1024.0) / (encrypt_time.count() / 1000.0)
              << " MB/s" << std::endl;
    std::cout << "Decryption throughput: "
              << std::fixed << std::setprecision(2)
              << (original_size / 1024.0 / 1024.0) / (decrypt_time.count() / 1000.0)
              << " MB/s" << std::endl;
    std::cout << "Size overhead: " << (encrypted_size - original_size) << " bytes ("
              << std::fixed << std::setprecision(2)
              << ((double)(encrypted_size - original_size) / original_size * 100) << "%)" << std::endl;
}

std::unique_ptr<des::DES> create_des_algorithm(const std::vector<std::byte>& key) {
    auto des_round_key_generation = std::make_shared<des::DesRoundKeyGeneration>();
    auto feistel_transformation = std::make_shared<des::FeistelTransformation>();
    return std::make_unique<des::DES>(key, des_round_key_generation, feistel_transformation);
}

// ==================== БАЗОВЫЕ ТЕСТЫ DES ====================

void test_ecb_encryption_decryption_des(TestRunner& runner) {
    runner.start_test("ECB Encryption/Decryption with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x13}, std::byte{0x34}, std::byte{0x57}, std::byte{0x79},
                std::byte{0x9B}, std::byte{0xBC}, std::byte{0xDF}, std::byte{0xF1}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF}
        };

        auto algorithm = create_des_algorithm(key);

        SymmetricContext algo(key, EncryptionModes::ECB, PaddingModes::PKCS7,
                              std::nullopt, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "ECB with DES: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_cbc_encryption_decryption_des(TestRunner& runner) {
    runner.start_test("CBC Encryption/Decryption with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}
        };

        auto algorithm = create_des_algorithm(key);

        SymmetricContext algo(key, EncryptionModes::CBC, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "CBC with DES: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_pcbc_encryption_decryption_des(TestRunner& runner) {
    runner.start_test("PCBC Encryption/Decryption with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}
        };

        auto algorithm = create_des_algorithm(key);

        SymmetricContext algo(key, EncryptionModes::PCBC, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "PCBC with DES: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_cfb_encryption_decryption_des(TestRunner& runner) {
    runner.start_test("CFB Encryption/Decryption with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}
        };

        auto algorithm = create_des_algorithm(key);

        SymmetricContext algo(key, EncryptionModes::CFB, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "CFB with DES: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_ofb_encryption_decryption_des(TestRunner& runner) {
    runner.start_test("OFB Encryption/Decryption with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}
        };

        auto algorithm = create_des_algorithm(key);

        SymmetricContext algo(key, EncryptionModes::OFB, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "OFB with DES: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_ctr_encryption_decryption_des(TestRunner& runner) {
    runner.start_test("CTR Encryption/Decryption with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}
        };

        auto algorithm = create_des_algorithm(key);

        SymmetricContext algo(key, EncryptionModes::CTR, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "CTR with DES: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_random_delta_encryption_decryption_des(TestRunner& runner) {
    runner.start_test("RandomDelta Encryption/Decryption with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}
        };

        auto algorithm = create_des_algorithm(key);

        SymmetricContext algo(key, EncryptionModes::RandomDelta, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "RandomDelta with DES: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_different_padding_modes_des(TestRunner& runner) {
    runner.start_test("Different Padding Modes with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22}
        };

        std::vector<std::vector<std::byte>> test_data_sets = {
                {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}},
                {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                        std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}},
                {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                        std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                        std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}}
        };

        std::vector<PaddingModes> padding_modes = {
                PaddingModes::ANSIX_923,
                PaddingModes::PKCS7,
                PaddingModes::ISO_10126
        };

        bool all_passed = true;

        for (auto padding_mode : padding_modes) {
            for (const auto& test_data : test_data_sets) {
                try {
                    auto algorithm = create_des_algorithm(key);

                    SymmetricContext algo(key, EncryptionModes::CBC, padding_mode,
                                          iv, {}, std::move(algorithm));

                    auto encrypted = algo.encrypt(test_data).get();
                    auto decrypted = algo.decrypt(encrypted).get();

                    if (!compare_byte_vectors(test_data, decrypted)) {
                        all_passed = false;
                        std::cout << "Padding mode " << static_cast<int>(padding_mode)
                                  << " failed for data size " << test_data.size() << std::endl;
                    }
                } catch (const std::exception& e) {
                    all_passed = false;
                    std::cout << "Padding mode " << static_cast<int>(padding_mode)
                              << " threw exception for data size " << test_data.size()
                              << ": " << e.what() << std::endl;
                }
            }
        }

        runner.assert_true(all_passed, "All padding modes should work correctly with DES");
        runner.end_test(all_passed);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_empty_data_des(TestRunner& runner) {
    runner.start_test("Empty Data Handling with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}
        };
        std::vector<std::byte> empty_data;

        auto algorithm = create_des_algorithm(key);

        SymmetricContext algo(key, EncryptionModes::ECB, PaddingModes::PKCS7,
                              std::nullopt, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(empty_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(decrypted.empty(), "Empty data should remain empty after encryption/decryption with DES");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_large_data_des(TestRunner& runner) {
    runner.start_test("Large Data Handling with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22}
        };

        std::vector<std::byte> large_data;
        for (int i = 0; i < 64; ++i) {
            large_data.push_back(static_cast<std::byte>(0x20 + i));
        }

        auto algorithm = create_des_algorithm(key);

        SymmetricContext algo(key, EncryptionModes::CBC, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypt_start = std::chrono::high_resolution_clock::now();
        auto encrypted = algo.encrypt(large_data).get();
        auto encrypt_end = std::chrono::high_resolution_clock::now();
        auto encrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(encrypt_end - encrypt_start);

        auto decrypt_start = std::chrono::high_resolution_clock::now();
        auto decrypted = algo.decrypt(encrypted).get();
        auto decrypt_end = std::chrono::high_resolution_clock::now();
        auto decrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(decrypt_end - decrypt_start);

        print_file_metrics("Large Data", large_data.size(), encrypted.size(), decrypted.size(),
                           encrypt_duration, decrypt_duration);

        bool data_matches = compare_byte_vectors(large_data, decrypted);

        runner.assert_true(data_matches && large_data.size() == decrypted.size(),
                           "Large data should be correctly encrypted and decrypted with DES");
        runner.end_test(data_matches && large_data.size() == decrypted.size());
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_thread_safety_des(TestRunner& runner) {
    runner.start_test("Thread Safety with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}
        };

        auto algorithm = create_des_algorithm(key);

        SymmetricContext algo(key, EncryptionModes::CBC, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        bool thread_safe = true;

        auto encrypt_task1 = algo.encrypt(test_data);
        auto encrypt_task2 = algo.encrypt(test_data);
        auto decrypt_task = algo.decrypt(test_data);

        auto encrypted1 = encrypt_task1.get();
        auto encrypted2 = encrypt_task2.get();
        auto decrypted = decrypt_task.get();

        auto final_decrypted = algo.decrypt(encrypted1).get();
        if (!compare_byte_vectors(test_data, final_decrypted)) {
            thread_safe = false;
            std::cout << "Thread safety check failed - decrypted data doesn't match original" << std::endl;
        }

        runner.assert_true(thread_safe, "Operations should be thread-safe with DES");
        runner.end_test(thread_safe);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

// ==================== ТЕСТЫ ФАЙЛОВ DES ====================

void test_text_file_operations_des(TestRunner& runner) {
    runner.start_test("Text File Operations with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22}
        };

        auto algorithm = create_des_algorithm(key);
        SymmetricContext cipher(key, EncryptionModes::CBC, PaddingModes::PKCS7, iv, {}, std::move(algorithm));

        std::filesystem::path base_dir = "tests\\test_des\\src";
        std::filesystem::create_directories(base_dir);

        // Используем пользовательский файл или создаем тестовый
        std::filesystem::path text_path;
        if (!test_config_des::text_file_path.empty()) {
            text_path = test_config_des::text_file_path;
            std::cout << "Using custom text file: " << text_path << std::endl;

            if (!std::filesystem::exists(text_path)) {
                std::cout << "✗ Custom text file not found: " << text_path << std::endl;
                runner.end_test(false);
                return;
            }
        } else {
            text_path = base_dir / "test_text_des.txt";
            std::cout << "Creating test text file: " << text_path << std::endl;

            std::ofstream text_file(text_path);
            text_file << "This is a comprehensive test text file for DES encryption.\n";
            text_file << "Testing file size measurement and timing metrics for text files.\n";
            text_file << "Multiple lines to ensure proper encryption/decryption process.\n";
            text_file << "Final line of text content for complete testing coverage.";
            text_file.close();
        }

        std::filesystem::path encrypted_path = base_dir / "encrypted_text_des.bin";
        std::filesystem::path decrypted_path = base_dir / "decrypted_text_des.txt";

        // Измерение времени шифрования
        auto encrypt_start = std::chrono::high_resolution_clock::now();
        std::optional<std::filesystem::path> opt_encrypted = encrypted_path;
        cipher.encrypt(text_path, opt_encrypted).get();
        auto encrypt_end = std::chrono::high_resolution_clock::now();
        auto encrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(encrypt_end - encrypt_start);

        // Измерение времени дешифрования
        auto decrypt_start = std::chrono::high_resolution_clock::now();
        std::optional<std::filesystem::path> opt_decrypted = decrypted_path;
        cipher.decrypt(encrypted_path, opt_decrypted).get();
        auto decrypt_end = std::chrono::high_resolution_clock::now();
        auto decrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(decrypt_end - decrypt_start);

        // Получение размеров файлов
        auto original_size = std::filesystem::file_size(text_path);
        auto encrypted_size = std::filesystem::file_size(encrypted_path);
        auto decrypted_size = std::filesystem::file_size(decrypted_path);

        // Вывод метрик
        print_file_metrics("Text File", original_size, encrypted_size, decrypted_size,
                           encrypt_duration, decrypt_duration);

        bool success = compare_files(text_path, decrypted_path);

        if (success) {
            std::cout << "✓ Text file encryption/decryption successful - files match perfectly" << std::endl;
        } else {
            std::cout << "✗ Text file encryption/decryption failed - file content mismatch" << std::endl;
        }

        runner.assert_true(success, "Text file content should match after DES encryption/decryption");
        runner.end_test(success);

    } catch (const std::exception& e) {
        std::cout << "Exception in text file test: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_binary_file_operations_des(TestRunner& runner) {
    runner.start_test("Binary File Operations with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22}
        };

        auto algorithm = create_des_algorithm(key);
        SymmetricContext cipher(key, EncryptionModes::CBC, PaddingModes::PKCS7, iv, {}, std::move(algorithm));

        std::filesystem::path base_dir = "tests\\test_des\\src";
        std::filesystem::create_directories(base_dir);

        // Используем пользовательский файл или создаем тестовый
        std::filesystem::path binary_path;
        if (!test_config_des::binary_file_path.empty()) {
            binary_path = test_config_des::binary_file_path;
            std::cout << "Using custom binary file: " << binary_path << std::endl;

            if (!std::filesystem::exists(binary_path)) {
                std::cout << "✗ Custom binary file not found: " << binary_path << std::endl;
                runner.end_test(false);
                return;
            }
        } else {
            binary_path = base_dir / "test_binary_des.bin";
            std::cout << "Creating test binary file: " << binary_path << std::endl;

            std::ofstream binary_file(binary_path, std::ios::binary);

            // Создание разнообразных бинарных данных (1MB)
            std::vector<unsigned char> test_binary_data;
            for (size_t i = 0; i < 1 * 1024 * 1024; ++i) {
                test_binary_data.push_back(static_cast<unsigned char>((i * 7) % 256));
            }
            binary_file.write(reinterpret_cast<const char*>(test_binary_data.data()), test_binary_data.size());
            binary_file.close();
        }

        std::filesystem::path encrypted_path = base_dir / "encrypted_binary_des.bin";
        std::filesystem::path decrypted_path = base_dir / "decrypted_binary_des.bin";

        // Измерение времени шифрования
        auto encrypt_start = std::chrono::high_resolution_clock::now();
        std::optional<std::filesystem::path> opt_encrypted = encrypted_path;
        cipher.encrypt(binary_path, opt_encrypted).get();
        auto encrypt_end = std::chrono::high_resolution_clock::now();
        auto encrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(encrypt_end - encrypt_start);

        // Измерение времени дешифрования
        auto decrypt_start = std::chrono::high_resolution_clock::now();
        std::optional<std::filesystem::path> opt_decrypted = decrypted_path;
        cipher.decrypt(encrypted_path, opt_decrypted).get();
        auto decrypt_end = std::chrono::high_resolution_clock::now();
        auto decrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(decrypt_end - decrypt_start);

        // Получение размеров файлов
        auto original_size = std::filesystem::file_size(binary_path);
        auto encrypted_size = std::filesystem::file_size(encrypted_path);
        auto decrypted_size = std::filesystem::file_size(decrypted_path);

        // Вывод метрик
        print_file_metrics("Binary File", original_size, encrypted_size, decrypted_size,
                           encrypt_duration, decrypt_duration);

        bool success = compare_files(binary_path, decrypted_path);

        if (success) {
            std::cout << "✓ Binary file encryption/decryption successful - files match perfectly" << std::endl;
        } else {
            std::cout << "✗ Binary file encryption/decryption failed - file content mismatch" << std::endl;
        }

        runner.assert_true(success, "Binary file content should match after DES encryption/decryption");
        runner.end_test(success);

    } catch (const std::exception& e) {
        std::cout << "Exception in binary file test: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_image_file_operations_des(TestRunner& runner) {
    runner.start_test("Image File Operations with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22}
        };

        auto algorithm = create_des_algorithm(key);
        SymmetricContext cipher(key, EncryptionModes::CBC, PaddingModes::PKCS7, iv, {}, std::move(algorithm));

        std::filesystem::path base_dir = "tests\\test_des\\src";
        std::filesystem::create_directories(base_dir);

        // Используем пользовательский файл или создаем тестовый
        std::filesystem::path image_path;
        if (!test_config_des::image_file_path.empty()) {
            image_path = test_config_des::image_file_path;
            std::cout << "Using custom image file: " << image_path << std::endl;

            if (!std::filesystem::exists(image_path)) {
                std::cout << "✗ Custom image file not found: " << image_path << std::endl;
                runner.end_test(false);
                return;
            }
        } else {
            image_path = base_dir / "test_image.jpg";
            std::cout << "Creating test image file: " << image_path << std::endl;

            // Создание простого JPEG файла
            std::ofstream image_file(image_path, std::ios::binary);
            // Простой JPEG заголовок для маленького черного изображения
            const unsigned char jpeg_data[] = {
                    0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
                    0x00, 0x01, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00,
                    0x10, 0x00, 0x10, 0x01, 0x01, 0x11, 0x00, 0xFF, 0xC4, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xFF, 0xDA, 0x00,
                    0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0x00, 0xFF, 0xD9
            };
            image_file.write(reinterpret_cast<const char*>(jpeg_data), sizeof(jpeg_data));
            image_file.close();
        }

        std::filesystem::path encrypted_path = base_dir / "encrypted_image_des.bin";
        std::filesystem::path decrypted_path = base_dir / "decrypted_image.jpg";

        // Измерение времени шифрования
        auto encrypt_start = std::chrono::high_resolution_clock::now();
        std::optional<std::filesystem::path> opt_encrypted = encrypted_path;
        cipher.encrypt(image_path, opt_encrypted).get();
        auto encrypt_end = std::chrono::high_resolution_clock::now();
        auto encrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(encrypt_end - encrypt_start);

        // Измерение времени дешифрования
        auto decrypt_start = std::chrono::high_resolution_clock::now();
        std::optional<std::filesystem::path> opt_decrypted = decrypted_path;
        cipher.decrypt(encrypted_path, opt_decrypted).get();
        auto decrypt_end = std::chrono::high_resolution_clock::now();
        auto decrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(decrypt_end - decrypt_start);

        // Получение размеров файлов
        auto original_size = std::filesystem::file_size(image_path);
        auto encrypted_size = std::filesystem::file_size(encrypted_path);
        auto decrypted_size = std::filesystem::file_size(decrypted_path);

        // Вывод метрик
        print_file_metrics("Image File", original_size, encrypted_size, decrypted_size,
                           encrypt_duration, decrypt_duration);

        bool success = compare_files(image_path, decrypted_path);

        if (success) {
            std::cout << "✓ Image file encryption/decryption successful - files match perfectly" << std::endl;
        } else {
            std::cout << "✗ Image file encryption/decryption failed - file content mismatch" << std::endl;
        }

        runner.assert_true(success, "Image file content should match after DES encryption/decryption");
        runner.end_test(success);

    } catch (const std::exception& e) {
        std::cout << "Exception in image file test: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_pdf_file_operations_des(TestRunner& runner) {
    runner.start_test("PDF File Operations with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22}
        };

        auto algorithm = create_des_algorithm(key);
        SymmetricContext cipher(key, EncryptionModes::CBC, PaddingModes::PKCS7, iv, {}, std::move(algorithm));

        std::filesystem::path base_dir = "tests\\test_des\\src";
        std::filesystem::create_directories(base_dir);

        // Используем пользовательский файл или создаем тестовый
        std::filesystem::path pdf_path;
        if (!test_config_des::pdf_file_path.empty()) {
            pdf_path = test_config_des::pdf_file_path;
            std::cout << "Using custom PDF file: " << pdf_path << std::endl;

            if (!std::filesystem::exists(pdf_path)) {
                std::cout << "✗ Custom PDF file not found: " << pdf_path << std::endl;
                runner.end_test(false);
                return;
            }
        } else {
            pdf_path = base_dir / "test_document.pdf";
            std::cout << "Creating test PDF file: " << pdf_path << std::endl;

            std::ofstream pdf_file(pdf_path);

            // Простой PDF контент
            pdf_file << "%PDF-1.4\n";
            pdf_file << "1 0 obj\n";
            pdf_file << "<< /Type /Catalog /Pages 2 0 R >>\n";
            pdf_file << "endobj\n";
            pdf_file << "2 0 obj\n";
            pdf_file << "<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n";
            pdf_file << "endobj\n";
            pdf_file << "3 0 obj\n";
            pdf_file << "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\n";
            pdf_file << "endobj\n";
            pdf_file << "4 0 obj\n";
            pdf_file << "<< /Length 44 >>\n";
            pdf_file << "stream\n";
            pdf_file << "BT /F1 24 Tf 100 700 Td (Test PDF Document) Tj ET\n";
            pdf_file << "endstream\n";
            pdf_file << "endobj\n";
            pdf_file << "xref\n";
            pdf_file << "0 5\n";
            pdf_file << "0000000000 65535 f \n";
            pdf_file << "0000000009 00000 n \n";
            pdf_file << "0000000058 00000 n \n";
            pdf_file << "0000000115 00000 n \n";
            pdf_file << "0000000234 00000 n \n";
            pdf_file << "trailer\n";
            pdf_file << "<< /Size 5 /Root 1 0 R >>\n";
            pdf_file << "startxref\n";
            pdf_file << "305\n";
            pdf_file << "%%EOF\n";

            pdf_file.close();
        }

        std::filesystem::path encrypted_path = base_dir / "encrypted_pdf_des.bin";
        std::filesystem::path decrypted_path = base_dir / "decrypted_document.pdf";

        // Измерение времени шифрования
        auto encrypt_start = std::chrono::high_resolution_clock::now();
        std::optional<std::filesystem::path> opt_encrypted = encrypted_path;
        cipher.encrypt(pdf_path, opt_encrypted).get();
        auto encrypt_end = std::chrono::high_resolution_clock::now();
        auto encrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(encrypt_end - encrypt_start);

        // Измерение времени дешифрования
        auto decrypt_start = std::chrono::high_resolution_clock::now();
        std::optional<std::filesystem::path> opt_decrypted = decrypted_path;
        cipher.decrypt(encrypted_path, opt_decrypted).get();
        auto decrypt_end = std::chrono::high_resolution_clock::now();
        auto decrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(decrypt_end - decrypt_start);

        // Получение размеров файлов
        auto original_size = std::filesystem::file_size(pdf_path);
        auto encrypted_size = std::filesystem::file_size(encrypted_path);
        auto decrypted_size = std::filesystem::file_size(decrypted_path);

        // Вывод метрик
        print_file_metrics("PDF File", original_size, encrypted_size, decrypted_size,
                           encrypt_duration, decrypt_duration);

        bool success = compare_files(pdf_path, decrypted_path);

        if (success) {
            std::cout << "✓ PDF file encryption/decryption successful - files match perfectly" << std::endl;
        } else {
            std::cout << "✗ PDF file encryption/decryption failed - file content mismatch" << std::endl;
        }

        runner.assert_true(success, "PDF file content should match after DES encryption/decryption");
        runner.end_test(success);

    } catch (const std::exception& e) {
        std::cout << "Exception in PDF file test: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_zip_file_operations_des(TestRunner& runner) {
    runner.start_test("ZIP File Operations with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22}
        };

        auto algorithm = create_des_algorithm(key);
        SymmetricContext cipher(key, EncryptionModes::CBC, PaddingModes::PKCS7, iv, {}, std::move(algorithm));

        std::filesystem::path base_dir = "tests\\test_des\\src";
        std::filesystem::create_directories(base_dir);

        // Используем пользовательский файл или создаем тестовый
        std::filesystem::path zip_path;
        if (!test_config_des::zip_file_path.empty()) {
            zip_path = test_config_des::zip_file_path;
            std::cout << "Using custom ZIP file: " << zip_path << std::endl;

            if (!std::filesystem::exists(zip_path)) {
                std::cout << "✗ Custom ZIP file not found: " << zip_path << std::endl;
                runner.end_test(false);
                return;
            }
        } else {
            zip_path = base_dir / "test_archive.zip";
            std::cout << "Creating test ZIP file: " << zip_path << std::endl;

            // Создание простого ZIP файла
            std::ofstream zip_file(zip_path, std::ios::binary);

            // Простой ZIP заголовок
            const char* zip_content = "PK\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00";
            zip_file.write(zip_content, 12);

            // Добавление тестовых данных в ZIP
            for (int i = 0; i < 3; ++i) {
                std::string file_content = "This is test file " + std::to_string(i + 1) + " in ZIP archive.\n";
                file_content += "Contains sample data for encryption testing.\n";
                zip_file.write(file_content.c_str(), file_content.size());
            }

            zip_file.close();
        }

        std::filesystem::path encrypted_path = base_dir / "encrypted_zip_des.bin";
        std::filesystem::path decrypted_path = base_dir / "decrypted_archive.zip";

        // Измерение времени шифрования
        auto encrypt_start = std::chrono::high_resolution_clock::now();
        std::optional<std::filesystem::path> opt_encrypted = encrypted_path;
        cipher.encrypt(zip_path, opt_encrypted).get();
        auto encrypt_end = std::chrono::high_resolution_clock::now();
        auto encrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(encrypt_end - encrypt_start);

        // Измерение времени дешифрования
        auto decrypt_start = std::chrono::high_resolution_clock::now();
        std::optional<std::filesystem::path> opt_decrypted = decrypted_path;
        cipher.decrypt(encrypted_path, opt_decrypted).get();
        auto decrypt_end = std::chrono::high_resolution_clock::now();
        auto decrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(decrypt_end - decrypt_start);

        // Получение размеров файлов
        auto original_size = std::filesystem::file_size(zip_path);
        auto encrypted_size = std::filesystem::file_size(encrypted_path);
        auto decrypted_size = std::filesystem::file_size(decrypted_path);

        // Вывод метрик
        print_file_metrics("ZIP File", original_size, encrypted_size, decrypted_size,
                           encrypt_duration, decrypt_duration);

        bool success = compare_files(zip_path, decrypted_path);

        if (success) {
            std::cout << "✓ ZIP file encryption/decryption successful - files match perfectly" << std::endl;
        } else {
            std::cout << "✗ ZIP file encryption/decryption failed - file content mismatch" << std::endl;
        }

        runner.assert_true(success, "ZIP file content should match after DES encryption/decryption");
        runner.end_test(success);

    } catch (const std::exception& e) {
        std::cout << "Exception in ZIP file test: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_mp4_file_operations_des(TestRunner& runner) {
    runner.start_test("MP4 File Operations with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22}
        };

        auto algorithm = create_des_algorithm(key);
        SymmetricContext cipher(key, EncryptionModes::CBC, PaddingModes::PKCS7, iv, {}, std::move(algorithm));

        std::filesystem::path base_dir = "tests\\test_des\\src";
        std::filesystem::create_directories(base_dir);

        // Используем пользовательский файл или создаем тестовый
        std::filesystem::path mp4_path;
        if (!test_config_des::mp4_file_path.empty()) {
            mp4_path = test_config_des::mp4_file_path;
            std::cout << "Using custom MP4 file: " << mp4_path << std::endl;

            if (!std::filesystem::exists(mp4_path)) {
                std::cout << "✗ Custom MP4 file not found: " << mp4_path << std::endl;
                runner.end_test(false);
                return;
            }
        } else {
            mp4_path = base_dir / "test_video.mp4";
            std::cout << "Creating test MP4 file: " << mp4_path << std::endl;

            std::ofstream mp4_file(mp4_path, std::ios::binary);

            // Создание простого контейнера с MP4-подобными данными
            const char* fake_mp4_header = "ftypmp42";
            mp4_file.write(fake_mp4_header, 8);

            // Добавление тестовых видео данных
            for (int frame = 0; frame < 100; ++frame) {
                std::string frame_data = "FRAME" + std::to_string(frame) + ":";
                // Имитация видеоданных
                for (int i = 0; i < 1024; ++i) {
                    frame_data += static_cast<char>((frame + i) % 256);
                }
                mp4_file.write(frame_data.c_str(), frame_data.size());
            }

            const char* fake_mp4_footer = "moov";
            mp4_file.write(fake_mp4_footer, 4);

            mp4_file.close();
        }

        std::filesystem::path encrypted_path = base_dir / "encrypted_mp4_des.bin";
        std::filesystem::path decrypted_path = base_dir / "decrypted_video.mp4";

        // Измерение времени шифрования
        auto encrypt_start = std::chrono::high_resolution_clock::now();
        std::optional<std::filesystem::path> opt_encrypted = encrypted_path;
        cipher.encrypt(mp4_path, opt_encrypted).get();
        auto encrypt_end = std::chrono::high_resolution_clock::now();
        auto encrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(encrypt_end - encrypt_start);

        // Измерение времени дешифрования
        auto decrypt_start = std::chrono::high_resolution_clock::now();
        std::optional<std::filesystem::path> opt_decrypted = decrypted_path;
        cipher.decrypt(encrypted_path, opt_decrypted).get();
        auto decrypt_end = std::chrono::high_resolution_clock::now();
        auto decrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(decrypt_end - decrypt_start);

        // Получение размеров файлов
        auto original_size = std::filesystem::file_size(mp4_path);
        auto encrypted_size = std::filesystem::file_size(encrypted_path);
        auto decrypted_size = std::filesystem::file_size(decrypted_path);

        // Вывод метрик
        print_file_metrics("MP4 File", original_size, encrypted_size, decrypted_size,
                           encrypt_duration, decrypt_duration);

        bool success = compare_files(mp4_path, decrypted_path);

        if (success) {
            std::cout << "✓ MP4 file encryption/decryption successful - files match perfectly" << std::endl;
        } else {
            std::cout << "✗ MP4 file encryption/decryption failed - file content mismatch" << std::endl;
        }

        runner.assert_true(success, "MP4 file content should match after DES encryption/decryption");
        runner.end_test(success);

    } catch (const std::exception& e) {
        std::cout << "Exception in MP4 file test: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

// ==================== ОСНОВНЫЕ ФУНКЦИИ ТЕСТИРОВАНИЯ ====================

int run_all_des_tests() {
    TestRunner runner;

    std::cout << "Running DES Symmetric Algorithm Tests" << std::endl;
    std::cout << "=====================================" << std::endl;

    try {
        // Базовые тесты DES
        test_ecb_encryption_decryption_des(runner);
        test_cbc_encryption_decryption_des(runner);
        test_pcbc_encryption_decryption_des(runner);
        test_cfb_encryption_decryption_des(runner);
        test_ofb_encryption_decryption_des(runner);
        test_ctr_encryption_decryption_des(runner);
        test_random_delta_encryption_decryption_des(runner);
        test_different_padding_modes_des(runner);
        test_empty_data_des(runner);
        test_large_data_des(runner);
        test_thread_safety_des(runner);

        // Тесты файлов с детальными метриками
        test_text_file_operations_des(runner);
        test_binary_file_operations_des(runner);
        test_image_file_operations_des(runner);
        test_pdf_file_operations_des(runner);
        test_zip_file_operations_des(runner);
        test_mp4_file_operations_des(runner);

    } catch (const std::exception& e) {
        std::cout << "DES Test interrupted by exception: " << e.what() << std::endl;
    }

    runner.print_summary();
    return runner.tests_failed > 0 ? 1 : 0;
}

void run_all_des_tests_with_custom_files(
        const std::filesystem::path& text_file,
        const std::filesystem::path& binary_file,
        const std::filesystem::path& image_file,
        const std::filesystem::path& pdf_file,
        const std::filesystem::path& zip_file,
        const std::filesystem::path& mp4_file
) {
    // Устанавливаем пользовательские файлы
    test_config_des::set_custom_files(text_file, binary_file, image_file, pdf_file, zip_file, mp4_file);

    // Запускаем тесты
    run_all_des_tests();
}