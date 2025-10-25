#include <iostream>
#include <vector>
#include <cassert>
#include <string>
#include <memory>
#include "symmetric_context.hpp"
#include "test_symmetric_context.hpp"

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

std::unique_ptr<des::DES> create_des_algorithm(const std::vector<std::byte>& key) {
    auto des_round_key_generation = std::make_shared<des::DesRoundKeyGeneration>();
    auto feistel_transformation = std::make_shared<des::FeistelTransformation>();
    return std::make_unique<des::DES>(key, des_round_key_generation, feistel_transformation);
}

void test_basic_des(TestRunner& runner) {
    runner.start_test("Basic DES Algorithm");

    try {
        std::vector<std::byte> key = {
                std::byte{0x13}, std::byte{0x34}, std::byte{0x57}, std::byte{0x79},
                std::byte{0x9B}, std::byte{0xBC}, std::byte{0xDF}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF}
        };

        auto algorithm = create_des_algorithm(key);

        std::cout << "Testing DES encrypt/decrypt directly" << std::endl;

        auto encrypted = algorithm->encrypt(test_data);
        std::cout << "Encrypted: ";
        print_byte_vector(encrypted);

        auto decrypted = algorithm->decrypt(encrypted);
        std::cout << "Decrypted: ";
        print_byte_vector(decrypted);

        std::cout << "Original:  ";
        print_byte_vector(test_data);

        bool success = compare_byte_vectors(test_data, decrypted);

        if (!success) {
            std::cout << "BASIC DES ALGORITHM IS BROKEN!" << std::endl;
        }

        runner.assert_true(success, "Basic DES algorithm should work correctly");
        runner.end_test(success);
    } catch (const std::exception& e) {
        std::cout << "Exception in basic DES test: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_ecb_encryption_decryption(TestRunner& runner) {
    runner.start_test("ECB Encryption/Decryption with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x13}, std::byte{0x34}, std::byte{0x57}, std::byte{0x79},
                std::byte{0x9B}, std::byte{0xBC}, std::byte{0xDF}
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

void test_cbc_encryption_decryption(TestRunner& runner) {
    runner.start_test("CBC Encryption/Decryption with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}
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
        algorithm->set_key(key);

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

void test_pcbc_encryption_decryption(TestRunner& runner) {
    runner.start_test("PCBC Encryption/Decryption with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}
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
        algorithm->set_key(key);

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

void test_cfb_encryption_decryption(TestRunner& runner) {
    runner.start_test("CFB Encryption/Decryption with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}
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
        algorithm->set_key(key);

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

void test_ofb_encryption_decryption(TestRunner& runner) {
    runner.start_test("OFB Encryption/Decryption with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}
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
        algorithm->set_key(key);

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

void test_ctr_encryption_decryption(TestRunner& runner) {
    runner.start_test("CTR Encryption/Decryption with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}
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
        algorithm->set_key(key);

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

void test_random_delta_encryption_decryption(TestRunner& runner) {
    runner.start_test("RandomDelta Encryption/Decryption with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}
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
        algorithm->set_key(key);

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

void test_different_padding_modes(TestRunner& runner) {
    runner.start_test("Different Padding Modes with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}
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
                    algorithm->set_key(key);

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

void test_empty_data(TestRunner& runner) {
    runner.start_test("Empty Data Handling with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}
        };
        std::vector<std::byte> empty_data;

        auto algorithm = create_des_algorithm(key);
        algorithm->set_key(key);

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

void test_large_data(TestRunner& runner) {
    runner.start_test("Large Data Handling with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}
        };
        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22}
        };

        std::vector<std::byte> large_data;
        for (int i = 0; i < 24; ++i) { 
            large_data.push_back(static_cast<std::byte>(0x20 + i)); 
        }

        auto algorithm = create_des_algorithm(key);
        algorithm->set_key(key);

        SymmetricContext algo(key, EncryptionModes::CBC, PaddingModes::PKCS7,
                                iv, {}, std::move(algorithm));

        std::cout << "\nStep 1 - Original data: " << large_data.size() << " bytes" << std::endl;

        auto encrypted = algo.encrypt(large_data).get();
        std::cout << "Step 2 - After encryption: " << encrypted.size() << " bytes" << std::endl;

        auto decrypted = algo.decrypt(encrypted).get();
        std::cout << "Step 3 - After decryption: " << decrypted.size() << " bytes" << std::endl;

        bool data_matches = compare_byte_vectors(large_data, decrypted);

        if (!data_matches) {
            std::cout << "Data content mismatch!" << std::endl;
            std::cout << "Original: ";
            print_byte_vector(large_data);
            std::cout << "Decrypted: ";
            print_byte_vector(decrypted);
        }

        runner.assert_true(data_matches && large_data.size() == decrypted.size(),
                           "Large data should be correctly encrypted and decrypted with DES");
        runner.end_test(data_matches && large_data.size() == decrypted.size());
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_thread_safety(TestRunner& runner) {
    runner.start_test("Thread Safety with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}
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
        algorithm->set_key(key);

        SymmetricContext algo(key, EncryptionModes::CBC, PaddingModes::PKCS7,
                                iv, {}, std::move(algorithm));

        bool thread_safe = true;

        auto encrypt_task1 = algo.encrypt(test_data);
        auto encrypt_task2 = algo.encrypt(test_data);
        auto decrypt_task = algo.decrypt(test_data);

        auto encrypted1 = encrypt_task1.get();
        auto encrypted2 = encrypt_task2.get();
        auto decrypted = decrypt_task.get();

        
        if (!compare_byte_vectors(encrypted1, encrypted2)) {
            std::cout << "Warning: Same plaintext encrypted to different ciphertexts (expected in CBC mode)" << std::endl;
        }

        
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

void test_image_and_text_files(TestRunner& runner) {
    runner.start_test("Image and Text Files Encryption with DES");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                std::byte{0x05}, std::byte{0x06}, std::byte{0x07}
        };
        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22}
        };

        auto algorithm = create_des_algorithm(key);
        algorithm->set_key(key);

        SymmetricContext cipher(
                key,
                EncryptionModes::CBC,
                PaddingModes::PKCS7,
                iv,
                {},
                std::move(algorithm)
        );

        // win std::filesystem::path base_dir = "C:\\Users\\анчоус\\CLionProjects\\CryptographyFundamentals\\tests\\test_symmetric_context\\src";
        // wsl std::filesystem::path base_dir =  "/mnt/c/Users/анчоус/CLionProjects/CryptographyFundamentals/tests/test_symmetric_context/src"
        // win 2 std::filesystem::path base_dir = "C:\CryptographyFundamentals\tests\test_symmetric_context\src"
        std::filesystem::path base_dir = "C:\\CryptographyFundamentals\\tests\\test_symmetric_context\\src";
        std::filesystem::create_directories(base_dir);

        {
            
            std::filesystem::path text_path = base_dir / "test_text.txt";
            std::ofstream text_file(text_path);
            text_file << "This is a test text file for DES encryption.\n";
            text_file << "Line 2: Testing DES symmetric algorithm.\n";
            text_file << "Line 3: Final line of text content.";
            text_file.close();

            std::cout << "Testing text file encryption with DES" << std::endl;

            std::filesystem::path encrypted_text_path = base_dir / "encrypted_text_des.bin";
            std::filesystem::path decrypted_text_path = base_dir / "decrypted_text_des.txt";

            std::optional<std::filesystem::path> opt_encrypted_text = encrypted_text_path;
            cipher.encrypt(text_path, opt_encrypted_text).get();

            std::optional<std::filesystem::path> opt_decrypted_text = decrypted_text_path;
            cipher.decrypt(encrypted_text_path, opt_decrypted_text).get();

            std::ifstream original_text(text_path);
            std::ifstream decrypted_text(decrypted_text_path);

            std::string original_content((std::istreambuf_iterator<char>(original_text)),
                                         std::istreambuf_iterator<char>());
            std::string decrypted_content((std::istreambuf_iterator<char>(decrypted_text)),
                                          std::istreambuf_iterator<char>());

            original_text.close();
            decrypted_text.close();

            runner.assert_equal(original_content, decrypted_content,
                                "Text file content should match after DES encryption/decryption");

            std::cout << "Text file test: Original " << original_content.size()
                      << " bytes, Decrypted " << decrypted_content.size() << " bytes" << std::endl;
        }

        {
            
            std::cout << "Testing binary file encryption with DES" << std::endl;

            std::filesystem::path binary_path = base_dir / "test_binary.bin";
            std::ofstream binary_file(binary_path, std::ios::binary);

            
            std::vector<unsigned char> test_binary_data = {
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
            };
            binary_file.write(reinterpret_cast<const char*>(test_binary_data.data()),
                              test_binary_data.size());
            binary_file.close();

            std::filesystem::path encrypted_binary_path = base_dir / "encrypted_binary_des.bin";
            std::filesystem::path decrypted_binary_path = base_dir / "decrypted_binary_des.bin";

            std::optional<std::filesystem::path> opt_encrypted_binary = encrypted_binary_path;
            cipher.encrypt(binary_path, opt_encrypted_binary).get();

            std::optional<std::filesystem::path> opt_decrypted_binary = decrypted_binary_path;
            cipher.decrypt(encrypted_binary_path, opt_decrypted_binary).get();

            auto original_size = std::filesystem::file_size(binary_path);
            auto encrypted_size = std::filesystem::file_size(encrypted_binary_path);
            auto decrypted_size = std::filesystem::file_size(decrypted_binary_path);

            std::cout << "Binary test: Original " << original_size << " bytes, "
                      << "Encrypted " << encrypted_size << " bytes, "
                      << "Decrypted " << decrypted_size << " bytes" << std::endl;

            runner.assert_true(original_size == decrypted_size,
                               "Binary file size should match after DES decryption");

            
            std::ifstream original_bin(binary_path, std::ios::binary);
            std::ifstream encrypted_bin(encrypted_binary_path, std::ios::binary);

            bool files_different = false;
            char orig_byte, enc_byte;
            for (size_t i = 0; i < std::min(original_size, encrypted_size) && i < 100; ++i) {
                original_bin.read(&orig_byte, 1);
                encrypted_bin.read(&enc_byte, 1);
                if (orig_byte != enc_byte) {
                    files_different = true;
                    break;
                }
            }

            original_bin.close();
            encrypted_bin.close();

            runner.assert_true(files_different, "Encrypted binary should be different from original");

            std::cout << "Binary encryption test completed successfully" << std::endl;
        }

        {
            // win path  std::filesystem::path img_path = "C:\\Users\\анчоус\\CLionProjects\\CryptographyFundamentals\\tests\\test_symmetric_context\\src\\SMILEFACE.jpg";
            // wsl path  std::filesystem::path img_path = "/mnt/c/Users/анчоус/CLionProjects/CryptographyFundamentals/tests/test_symmetric_context/src/SMILEFACE.jpg";
            // win 2 path std::filesystem::path img_path = "C:\CryptographyFundamentals\tests\test_symmetric_context\src\SMILEFACE.jpg"
            std::filesystem::path img_path = "C:\\CryptographyFundamentals\\tests\\test_symmetric_context\\src\\SMILEFACE.jpg";
            std::cout << "Testing img file encryption with DES" << std::endl;

            std::filesystem::path encrypted_img_path = base_dir / "encrypted_img_des.bin";
            std::filesystem::path decrypted_img_path = base_dir / "decrypted_img_des.jpg";

            std::optional<std::filesystem::path> opt_encrypted_img = encrypted_img_path;
            cipher.encrypt(img_path, opt_encrypted_img).get();

            std::optional<std::filesystem::path> opt_decrypted_img = decrypted_img_path;
            cipher.decrypt(encrypted_img_path, opt_decrypted_img).get();

            std::ifstream original_img(img_path);
            std::ifstream decrypted_img(decrypted_img_path);

            std::string original_content((std::istreambuf_iterator<char>(original_img)),
                                         std::istreambuf_iterator<char>());
            std::string decrypted_content((std::istreambuf_iterator<char>(decrypted_img)),
                                          std::istreambuf_iterator<char>());

            original_img.close();
            decrypted_img.close();

            runner.assert_equal(original_content, decrypted_content,
                                "Img file content should match after DES encryption/decryption");

            std::cout << "Img file test: Original " << std::filesystem::file_size(img_path)
                      << " bytes, Decrypted " << std::filesystem::file_size(decrypted_img_path) << " bytes" << std::endl;
        }

        std::cout << "All test files saved in: " << base_dir << std::endl;
        runner.end_test(true);

    } catch (const std::exception& e) {
        std::cout << "Exception in file test with DES: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

int run_all_tests() {
    TestRunner runner;

    std::cout << "Running DES Symmetric Algorithm Tests" << std::endl;
    std::cout << "========================================" << std::endl;

    try {
        test_basic_des(runner);
        test_ecb_encryption_decryption(runner);
        test_cbc_encryption_decryption(runner);
        test_pcbc_encryption_decryption(runner);
        test_cfb_encryption_decryption(runner);
        test_ofb_encryption_decryption(runner);
        test_ctr_encryption_decryption(runner);
        test_random_delta_encryption_decryption(runner);
        test_different_padding_modes(runner);
        test_empty_data(runner);
        test_large_data(runner);
        test_thread_safety(runner);
        test_image_and_text_files(runner);
    } catch (const std::exception& e) {
        std::cout << "Test interrupted by exception: " << e.what() << std::endl;
    }

    runner.print_summary();

    return runner.tests_failed > 0 ? 1 : 0;
}