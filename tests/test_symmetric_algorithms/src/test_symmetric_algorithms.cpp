#include "test_symmetric_algorithms.hpp"

void TestRunner::start_test(const std::string& test_name) {
    current_test = test_name;
    std::cout << "TEST: " << test_name << " ... ";
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

void print_byte_vector(const std::vector<std::byte>& data) {
    std::cout << "Vector size: " << data.size() << " [";
    for (size_t i = 0; i < std::min(data.size(), size_t(10)); ++i) {
        std::cout << std::hex << static_cast<int>(data[i]) << " ";
    }
    if (data.size() > 10) std::cout << "...";
    std::cout << "]" << std::dec << std::endl;
}

void test_ecb_encryption_decryption(TestRunner& runner) {
    runner.start_test("ECB Encryption/Decryption");

    try {
        std::vector<std::byte> key = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
        std::vector<std::byte> test_data = {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}};

        auto algorithm = std::make_unique<TestEncryption>();
        algorithm->set_key(key);

        size_t block_size = algorithm->get_block_size();
        if (block_size == 0) {
            throw std::runtime_error("Block size is 0!");
        }

        SymmetricAlgorithm algo(key, EncryptionModes::ECB, PaddingModes::PKCS7,
                                std::nullopt, {}, std::move(algorithm));

        auto encrypted_future = algo.encrypt(test_data);
        auto encrypted = encrypted_future.get();

        std::cout << "Original size: " << test_data.size()
                  << ", Encrypted size: " << encrypted.size() << std::endl;

        auto decrypted_future = algo.decrypt(encrypted);
        auto decrypted = decrypted_future.get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "ECB: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_cbc_encryption_decryption(TestRunner& runner) {
    runner.start_test("CBC Encryption/Decryption");

    try {
        std::vector<std::byte> key = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
        std::vector<std::byte> iv = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD}};
        std::vector<std::byte> test_data = {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}};

        auto algorithm = std::make_unique<TestEncryption>();
        algorithm->set_key(key);

        SymmetricAlgorithm algo(key, EncryptionModes::CBC, PaddingModes::PKCS7,
                                iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "CBC: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_pcbc_encryption_decryption(TestRunner& runner) {
    runner.start_test("PCBC Encryption/Decryption");

    try {
        std::vector<std::byte> key = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
        std::vector<std::byte> iv = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD}};
        std::vector<std::byte> test_data = {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}};

        auto algorithm = std::make_unique<TestEncryption>();
        algorithm->set_key(key);

        SymmetricAlgorithm algo(key, EncryptionModes::PCBC, PaddingModes::PKCS7,
                                iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "PCBC: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_cfb_encryption_decryption(TestRunner& runner) {
    runner.start_test("CFB Encryption/Decryption");

    try {
        std::vector<std::byte> key = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
        std::vector<std::byte> iv = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD}};
        std::vector<std::byte> test_data = {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}};

        auto algorithm = std::make_unique<TestEncryption>();
        algorithm->set_key(key);

        SymmetricAlgorithm algo(key, EncryptionModes::CFB, PaddingModes::PKCS7,
                                iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "CFB: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_ofb_encryption_decryption(TestRunner& runner) {
    runner.start_test("OFB Encryption/Decryption");

    try {
        std::vector<std::byte> key = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
        std::vector<std::byte> iv = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD}};
        std::vector<std::byte> test_data = {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}};

        auto algorithm = std::make_unique<TestEncryption>();
        algorithm->set_key(key);

        SymmetricAlgorithm algo(key, EncryptionModes::OFB, PaddingModes::PKCS7,
                                iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "OFB: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_ctr_encryption_decryption(TestRunner& runner) {
    runner.start_test("CTR Encryption/Decryption");

    try {
        std::vector<std::byte> key = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
        std::vector<std::byte> iv = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD}};
        std::vector<std::byte> test_data = {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}};

        auto algorithm = std::make_unique<TestEncryption>();
        algorithm->set_key(key);

        SymmetricAlgorithm algo(key, EncryptionModes::CTR, PaddingModes::PKCS7,
                                iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "CTR: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_random_delta_encryption_decryption(TestRunner& runner) {
    runner.start_test("RandomDelta Encryption/Decryption");

    try {
        std::vector<std::byte> key = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
        std::vector<std::byte> iv = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD}};
        std::vector<std::byte> test_data = {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}};

        auto algorithm = std::make_unique<TestEncryption>();
        algorithm->set_key(key);

        SymmetricAlgorithm algo(key, EncryptionModes::RandomDelta, PaddingModes::PKCS7,
                                iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "RandomDelta: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_different_padding_modes(TestRunner& runner) {
    runner.start_test("Different Padding Modes");

    try {
        std::vector<std::byte> key = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
        std::vector<std::byte> iv = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD}};
        std::vector<std::byte> test_data = {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}};

        std::vector<PaddingModes> padding_modes = {
                PaddingModes::ANSIX_923,
                PaddingModes::PKCS7,
                PaddingModes::ISO_10126
        };

        bool all_passed = true;

        for (auto padding_mode : padding_modes) {
            try {
                auto algorithm = std::make_unique<TestEncryption>();
                algorithm->set_key(key);

                SymmetricAlgorithm algo(key, EncryptionModes::CBC, padding_mode,
                                        iv, {}, std::move(algorithm));

                auto encrypted = algo.encrypt(test_data).get();
                auto decrypted = algo.decrypt(encrypted).get();

                if (!compare_byte_vectors(test_data, decrypted)) {
                    all_passed = false;
                    std::cout << "Padding mode " << static_cast<int>(padding_mode) << " failed" << std::endl;
                    std::cout << "Original size: " << test_data.size()
                              << ", Decrypted size: " << decrypted.size() << std::endl;
                }
            } catch (const std::exception& e) {
                all_passed = false;
                std::cout << "Padding mode " << static_cast<int>(padding_mode)
                          << " threw exception: " << e.what() << std::endl;
            }
        }

        runner.assert_true(all_passed, "All padding modes should work correctly");
        runner.end_test(all_passed);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_empty_data(TestRunner& runner) {
    runner.start_test("Empty Data Handling");

    try {
        std::vector<std::byte> key = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
        std::vector<std::byte> empty_data;

        auto algorithm = std::make_unique<TestEncryption>();
        algorithm->set_key(key);

        SymmetricAlgorithm algo(key, EncryptionModes::ECB, PaddingModes::PKCS7,
                                std::nullopt, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(empty_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(decrypted.empty(), "Empty data should remain empty after encryption/decryption");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_large_data(TestRunner& runner) {
    runner.start_test("Large Data Handling");

    try {
        std::vector<std::byte> key = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
        std::vector<std::byte> iv = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD}};

        std::vector<std::byte> large_data;
        for (int i = 0; i < 17; ++i) {
            large_data.push_back(static_cast<std::byte>(0xAB + i));
        }

        auto algorithm = std::make_unique<TestEncryption>();
        algorithm->set_key(key);

        SymmetricAlgorithm algo(key, EncryptionModes::CBC, PaddingModes::PKCS7,
                                iv, {}, std::move(algorithm));

        std::cout << "Step 1 - Original data: " << large_data.size() << " bytes" << std::endl;

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
                           "Large data should be correctly encrypted and decrypted");
        runner.end_test(data_matches && large_data.size() == decrypted.size());
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_thread_safety(TestRunner& runner) {
    runner.start_test("Thread Safety");

    try {
        std::vector<std::byte> key = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
        std::vector<std::byte> iv = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD}};
        std::vector<std::byte> test_data = {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}};

        auto algorithm = std::make_unique<TestEncryption>();
        algorithm->set_key(key);

        SymmetricAlgorithm algo(key, EncryptionModes::CBC, PaddingModes::PKCS7,
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

        runner.assert_true(thread_safe, "Operations should be thread-safe");
        runner.end_test(thread_safe);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_image_and_text_files(TestRunner& runner) {
    runner.start_test("Image and Text Files Encryption");

    try {
        std::vector<std::byte> key = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                                      std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}};
        std::vector<std::byte> iv = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                                     std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22}};

        auto algorithm = std::make_unique<TestEncryption>();
        algorithm->set_key(key);

        SymmetricAlgorithm cipher(
                key,
                EncryptionModes::CBC,
                PaddingModes::PKCS7,
                iv,
                {},
                std::move(algorithm)
        );


        std::filesystem::path base_dir = "C:\\CryptographyFundamentals\\tests\\test_symmetric_algorithms\\src\\";

        {
            std::filesystem::path text_path = base_dir / "test_text.txt";
            std::ofstream text_file(text_path);
            text_file << "This is a test text file for encryption.\n";
            text_file << "Line 2: Testing symmetric algorithm.\n";
            text_file << "Line 3: Final line of text content.";
            text_file.close();

            std::cout << "Testing text file encryption..." << std::endl;

            std::filesystem::path encrypted_text_path = base_dir / "encrypted_text.bin";
            std::filesystem::path decrypted_text_path = base_dir / "decrypted_text.txt";

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
                                "Text file content should match after encryption/decryption");

            std::cout << "Text file test: Original " << original_content.size()
                      << " bytes, Decrypted " << decrypted_content.size() << " bytes" << std::endl;
            std::cout << "Text files saved in: " << base_dir << std::endl;
        }

        {
            std::cout << "Testing image file encryption..." << std::endl;

            std::filesystem::path img = "C:\\CryptographyFundamentals\\tests\\test_symmetric_algorithms\\src\\SMILEFACE.jpg";

            if (!std::filesystem::exists(img)) {
                std::cout << "Image file not found: " << img << std::endl;
                runner.end_test(false);
                return;
            }

            std::filesystem::path encrypted_image_path = img.parent_path() / "encrypted_SMILEFACE.bin";
            std::filesystem::path decrypted_image_path = img.parent_path() / "decrypted_SMILEFACE.jpg";

            std::optional<std::filesystem::path> opt_encrypted_image = encrypted_image_path;
            cipher.encrypt(img, opt_encrypted_image).get();

            std::optional<std::filesystem::path> opt_decrypted_image = decrypted_image_path;
            cipher.decrypt(encrypted_image_path, opt_decrypted_image).get();

            auto original_size = std::filesystem::file_size(img);
            auto encrypted_size = std::filesystem::file_size(encrypted_image_path);
            auto decrypted_size = std::filesystem::file_size(decrypted_image_path);

            std::cout << "Image test: Original " << original_size << " bytes, "
                      << "Encrypted " << encrypted_size << " bytes, "
                      << "Decrypted " << decrypted_size << " bytes" << std::endl;

            runner.assert_true(original_size == decrypted_size,
                               "Image file size should match after decryption");

            std::ifstream original_img(img, std::ios::binary);
            std::ifstream encrypted_img(encrypted_image_path, std::ios::binary);

            bool files_different = false;
            char orig_byte, enc_byte;
            for (size_t i = 0; i < std::min(original_size, encrypted_size) && i < 100; ++i) {
                original_img.read(&orig_byte, 1);
                encrypted_img.read(&enc_byte, 1);
                if (orig_byte != enc_byte) {
                    files_different = true;
                    break;
                }
            }

            original_img.close();
            encrypted_img.close();

            runner.assert_true(files_different, "Encrypted image should be different from original");

            std::cout << "Image encryption test completed successfully" << std::endl;
            std::cout << "Encrypted file: " << encrypted_image_path << std::endl;
            std::cout << "Decrypted file: " << decrypted_image_path << std::endl;
        }


        runner.end_test(true);

    } catch (const std::exception& e) {
        std::cout << "Exception in image/text test: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

int run_all_tests() {
    TestRunner runner;

    std::cout << "Running Symmetric Algorithm Tests..." << std::endl;
    std::cout << "=====================================" << std::endl;

    try {

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
