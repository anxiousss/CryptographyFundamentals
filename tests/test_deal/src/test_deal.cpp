#include "test_deal.hpp"

namespace test_config {
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

        std::cout << "Custom files configuration:" << std::endl;
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


std::unique_ptr<deal::DEAL> create_deal_algorithm_128(const std::vector<std::byte>& key) {
    auto deal_round_key_generation = std::make_shared<deal::DealRoundKeyGeneration>();
    auto des_transformation = std::make_shared<deal::DesTransformation>();
    return std::make_unique<deal::DEAL>(key, deal_round_key_generation, des_transformation);
}

std::unique_ptr<deal::DEAL> create_deal_algorithm_192(const std::vector<std::byte>& key) {
    auto deal_round_key_generation = std::make_shared<deal::DealRoundKeyGeneration>();
    auto des_transformation = std::make_shared<deal::DesTransformation>();
    return std::make_unique<deal::DEAL>(key, deal_round_key_generation, des_transformation);
}

std::unique_ptr<deal::DEAL> create_deal_algorithm_256(const std::vector<std::byte>& key) {
    auto deal_round_key_generation = std::make_shared<deal::DealRoundKeyGeneration>();
    auto des_transformation = std::make_shared<deal::DesTransformation>();
    return std::make_unique<deal::DEAL>(key, deal_round_key_generation, des_transformation);
}

// ==================== TESTS FOR DEAL ====================

void test_ecb_encryption_decryption_deal(TestRunner& runner) {
    runner.start_test("ECB Encryption/Decryption with DEAL");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10}
        };

        auto algorithm = create_deal_algorithm_128(key);

        SymmetricContext algo(key, EncryptionModes::ECB, PaddingModes::PKCS7,
                              std::nullopt, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "ECB with DEAL: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_cbc_encryption_decryption_deal(TestRunner& runner) {
    runner.start_test("CBC Encryption/Decryption with DEAL");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_128(key);

        SymmetricContext algo(key, EncryptionModes::CBC, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "CBC with DEAL: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_pcbc_encryption_decryption_deal(TestRunner& runner) {
    runner.start_test("PCBC Encryption/Decryption with DEAL");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_128(key);

        SymmetricContext algo(key, EncryptionModes::PCBC, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "PCBC with DEAL: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_cfb_encryption_decryption_deal(TestRunner& runner) {
    runner.start_test("CFB Encryption/Decryption with DEAL");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_128(key);

        SymmetricContext algo(key, EncryptionModes::CFB, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "CFB with DEAL: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_ofb_encryption_decryption_deal(TestRunner& runner) {
    runner.start_test("OFB Encryption/Decryption with DEAL");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_128(key);

        SymmetricContext algo(key, EncryptionModes::OFB, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "OFB with DEAL: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_ctr_encryption_decryption_deal(TestRunner& runner) {
    runner.start_test("CTR Encryption/Decryption with DEAL");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_128(key);

        SymmetricContext algo(key, EncryptionModes::CTR, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "CTR with DEAL: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_random_delta_encryption_decryption_deal(TestRunner& runner) {
    runner.start_test("RandomDelta Encryption/Decryption with DEAL");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_128(key);

        SymmetricContext algo(key, EncryptionModes::RandomDelta, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "RandomDelta with DEAL: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_different_padding_modes_deal(TestRunner& runner) {
    runner.start_test("Different Padding Modes with DEAL");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        std::vector<std::vector<std::byte>> test_data_sets = {
                {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}},
                {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                        std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                        std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                        std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}},
                {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                        std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                        std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                        std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00},
                        std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                        std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}}
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
                    auto algorithm = create_deal_algorithm_128(key);

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

        runner.assert_true(all_passed, "All padding modes should work correctly with DEAL");
        runner.end_test(all_passed);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_empty_data_deal(TestRunner& runner) {
    runner.start_test("Empty Data Handling with DEAL");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10}
        };
        std::vector<std::byte> empty_data;

        auto algorithm = create_deal_algorithm_128(key);

        SymmetricContext algo(key, EncryptionModes::ECB, PaddingModes::PKCS7,
                              std::nullopt, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(empty_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(decrypted.empty(), "Empty data should remain empty after encryption/decryption with DEAL");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_large_data_deal(TestRunner& runner) {
    runner.start_test("Large Data Handling with DEAL");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        std::vector<std::byte> large_data;
        for (int i = 0; i < 64; ++i) {
            large_data.push_back(static_cast<std::byte>(0x20 + i));
        }

        auto algorithm = create_deal_algorithm_128(key);

        SymmetricContext algo(key, EncryptionModes::CBC, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        std::cout << "\nStep 1 - Original data: " << large_data.size() << " bytes" << std::endl;

        auto encrypted = algo.encrypt(large_data).get();
        std::cout << "Step 2 - After encryption: " << encrypted.size() << " bytes" << std::endl;

        auto decrypted = algo.decrypt(encrypted).get();
        std::cout << "Step 3 - After decryption: " << decrypted.size() << " bytes" << std::endl;

        bool data_matches = compare_byte_vectors(large_data, decrypted);

        runner.assert_true(data_matches && large_data.size() == decrypted.size(),
                           "Large data should be correctly encrypted and decrypted with DEAL");
        runner.end_test(data_matches && large_data.size() == decrypted.size());
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_thread_safety_deal(TestRunner& runner) {
    runner.start_test("Thread Safety with DEAL");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_128(key);

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

        runner.assert_true(thread_safe, "Operations should be thread-safe with DEAL");
        runner.end_test(thread_safe);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_image_and_text_files_deal(TestRunner& runner) {
    runner.start_test("Image and Text Files Encryption with DEAL");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_128(key);

        SymmetricContext cipher(
                key,
                EncryptionModes::CBC,
                PaddingModes::PKCS7,
                iv,
                {},
                std::move(algorithm)
        );

        std::filesystem::path base_dir = "tests\\test_deal\\src";
        std::filesystem::create_directories(base_dir);

        {
            std::filesystem::path text_path = base_dir / "test_text_deal.txt";
            std::ofstream text_file(text_path);
            text_file << "This is a test text file for DEAL encryption.\n";
            text_file << "DEAL uses 128-bit blocks and supports 128, 192, 256-bit keys.\n";
            text_file << "Final line of text content for DEAL testing.";
            text_file.close();

            std::cout << "Testing text file encryption with DEAL" << std::endl;

            std::filesystem::path encrypted_text_path = base_dir / "encrypted_text_deal.bin";
            std::filesystem::path decrypted_text_path = base_dir / "decrypted_text_deal.txt";

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
                                "Text file content should match after DEAL encryption/decryption");

            std::cout << "Text file test: Original " << original_content.size()
                      << " bytes, Decrypted " << decrypted_content.size() << " bytes" << std::endl;
        }

        {
            std::cout << "Testing binary file encryption with DEAL" << std::endl;

            std::filesystem::path binary_path = base_dir / "test_binary_deal.bin";
            std::ofstream binary_file(binary_path, std::ios::binary);

            std::vector<unsigned char> test_binary_data;
            for (int i = 0; i < 48; ++i) {
                test_binary_data.push_back(static_cast<unsigned char>(i));
            }
            binary_file.write(reinterpret_cast<const char*>(test_binary_data.data()),
                              test_binary_data.size());
            binary_file.close();

            std::filesystem::path encrypted_binary_path = base_dir / "encrypted_binary_deal.bin";
            std::filesystem::path decrypted_binary_path = base_dir / "decrypted_binary_deal.bin";

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
                               "Binary file size should match after DEAL decryption");

            std::cout << "Binary encryption test completed successfully" << std::endl;
        }

        {
            std::filesystem::path img_path = "SMILEFACE.jpg";
            std::cout << "Testing img file encryption with DEAL " << std::endl;

            std::filesystem::path encrypted_img_path = base_dir / "encrypted_img_deal.bin";
            std::filesystem::path decrypted_img_path = base_dir / "decrypted_img_deal.jpg";

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
                                "Img file content should match after DEAL encryption/decryption");

            std::cout << "Img file test: Original " << std::filesystem::file_size(img_path)
                      << " bytes, Decrypted " << std::filesystem::file_size(decrypted_img_path) << " bytes" << std::endl;
        }

        std::cout << "All DEAL test files saved in: " << base_dir << std::endl;
        runner.end_test(true);

    } catch (const std::exception& e) {
        std::cout << "Exception in file test with DEAL: " << e.what() << std::endl;
        runner.end_test(false);
    }
}


void test_ecb_deal_192(TestRunner& runner) {
    runner.start_test("ECB Mode with DEAL-192");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10},
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10}
        };

        auto algorithm = create_deal_algorithm_192(key);

        SymmetricContext algo(key, EncryptionModes::ECB, PaddingModes::PKCS7,
                              std::nullopt, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "ECB with DEAL-192: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_cbc_deal_192(TestRunner& runner) {
    runner.start_test("CBC Mode with DEAL-192");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10},
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_192(key);

        SymmetricContext algo(key, EncryptionModes::CBC, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "CBC with DEAL-192: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_pcbc_deal_192(TestRunner& runner) {
    runner.start_test("PCBC Mode with DEAL-192");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10},
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_192(key);

        SymmetricContext algo(key, EncryptionModes::PCBC, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "PCBC with DEAL-192: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_cfb_deal_192(TestRunner& runner) {
    runner.start_test("CFB Mode with DEAL-192");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10},
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_192(key);

        SymmetricContext algo(key, EncryptionModes::CFB, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "CFB with DEAL-192: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_ofb_deal_192(TestRunner& runner) {
    runner.start_test("OFB Mode with DEAL-192");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10},
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_192(key);

        SymmetricContext algo(key, EncryptionModes::OFB, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "OFB with DEAL-192: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_ctr_deal_192(TestRunner& runner) {
    runner.start_test("CTR Mode with DEAL-192");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10},
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_192(key);

        SymmetricContext algo(key, EncryptionModes::CTR, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "CTR with DEAL-192: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_random_delta_deal_192(TestRunner& runner) {
    runner.start_test("RandomDelta Mode with DEAL-192");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10},
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_192(key);

        SymmetricContext algo(key, EncryptionModes::RandomDelta, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "RandomDelta with DEAL-192: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

// ==================== DEAL-256 TESTS ====================

void test_ecb_deal_256(TestRunner& runner) {
    runner.start_test("ECB Mode with DEAL-256");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10},
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10}
        };

        auto algorithm = create_deal_algorithm_256(key);

        SymmetricContext algo(key, EncryptionModes::ECB, PaddingModes::PKCS7,
                              std::nullopt, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "ECB with DEAL-256: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_cbc_deal_256(TestRunner& runner) {
    runner.start_test("CBC Mode with DEAL-256");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10},
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_256(key);

        SymmetricContext algo(key, EncryptionModes::CBC, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "CBC with DEAL-256: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_pcbc_deal_256(TestRunner& runner) {
    runner.start_test("PCBC Mode with DEAL-256");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10},
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_256(key);

        SymmetricContext algo(key, EncryptionModes::PCBC, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "PCBC with DEAL-256: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_cfb_deal_256(TestRunner& runner) {
    runner.start_test("CFB Mode with DEAL-256");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10},
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_256(key);

        SymmetricContext algo(key, EncryptionModes::CFB, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "CFB with DEAL-256: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_ofb_deal_256(TestRunner& runner) {
    runner.start_test("OFB Mode with DEAL-256");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10},
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_256(key);

        SymmetricContext algo(key, EncryptionModes::OFB, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "OFB with DEAL-256: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_ctr_deal_256(TestRunner& runner) {
    runner.start_test("CTR Mode with DEAL-256");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10},
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_256(key);

        SymmetricContext algo(key, EncryptionModes::CTR, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "CTR with DEAL-256: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_random_delta_deal_256(TestRunner& runner) {
    runner.start_test("RandomDelta Mode with DEAL-256");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10},
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_256(key);

        SymmetricContext algo(key, EncryptionModes::RandomDelta, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(test_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "RandomDelta with DEAL-256: Original and decrypted data should match");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}


void test_large_data_deal_192(TestRunner& runner) {
    runner.start_test("Large Data with DEAL-192");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10},
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        std::vector<std::byte> large_data;
        for (int i = 0; i < 80; ++i) {
            large_data.push_back(static_cast<std::byte>(0x20 + i));
        }

        auto algorithm = create_deal_algorithm_192(key);

        SymmetricContext algo(key, EncryptionModes::CBC, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(large_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        bool success = compare_byte_vectors(large_data, decrypted);

        runner.assert_true(success, "Large data should be correctly encrypted and decrypted with DEAL-192");
        runner.end_test(success);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_large_data_deal_256(TestRunner& runner) {
    runner.start_test("Large Data with DEAL-256");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10},
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        std::vector<std::byte> large_data;
        for (int i = 0; i < 96; ++i) {
            large_data.push_back(static_cast<std::byte>(0x20 + i));
        }

        auto algorithm = create_deal_algorithm_256(key);

        SymmetricContext algo(key, EncryptionModes::CBC, PaddingModes::PKCS7,
                              iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(large_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        bool success = compare_byte_vectors(large_data, decrypted);

        runner.assert_true(success, "Large data should be correctly encrypted and decrypted with DEAL-256");
        runner.end_test(success);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_different_padding_modes_deal_192(TestRunner& runner) {
    runner.start_test("Different Padding Modes with DEAL-192");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10},
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        std::vector<std::vector<std::byte>> test_data_sets = {
                {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}},
                {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                        std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                        std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                        std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}},
                {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                        std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                        std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                        std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00},
                        std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                        std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}}
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
                    auto algorithm = create_deal_algorithm_192(key);

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

        runner.assert_true(all_passed, "All padding modes should work correctly with DEAL-192");
        runner.end_test(all_passed);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_different_padding_modes_deal_256(TestRunner& runner) {
    runner.start_test("Different Padding Modes with DEAL-256");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10},
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        std::vector<std::vector<std::byte>> test_data_sets = {
                {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}},
                {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                        std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                        std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                        std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}},
                {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                        std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                        std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                        std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00},
                        std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                        std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                        std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                        std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}}
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
                    auto algorithm = create_deal_algorithm_256(key);

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

        runner.assert_true(all_passed, "All padding modes should work correctly with DEAL-256");
        runner.end_test(all_passed);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_file_operations_deal_192(TestRunner& runner) {
    runner.start_test("File Operations with DEAL-192");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10},
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_192(key);

        SymmetricContext cipher(key, EncryptionModes::CBC, PaddingModes::PKCS7,
                                iv, {}, std::move(algorithm));

        std::filesystem::path base_dir = "tests\\test_deal\\src";
        std::filesystem::create_directories(base_dir);

        std::filesystem::path text_path = base_dir / "test_deal_192.txt";
        std::ofstream text_file(text_path);
        text_file << "DEAL-192 Test File Content\n";
        text_file << "This file tests DEAL-192 algorithm with 192-bit key\n";
        text_file << "Multiple lines to ensure proper encryption/decryption\n";
        text_file.close();

        std::filesystem::path encrypted_path = base_dir / "encrypted_deal_192.bin";
        std::filesystem::path decrypted_path = base_dir / "decrypted_deal_192.txt";

        std::optional<std::filesystem::path> opt_encrypted = encrypted_path;
        cipher.encrypt(text_path, opt_encrypted).get();

        std::optional<std::filesystem::path> opt_decrypted = decrypted_path;
        cipher.decrypt(encrypted_path, opt_decrypted).get();

        std::ifstream original_file(text_path);
        std::ifstream decrypted_file(decrypted_path);

        std::string original_content((std::istreambuf_iterator<char>(original_file)),
                                     std::istreambuf_iterator<char>());
        std::string decrypted_content((std::istreambuf_iterator<char>(decrypted_file)),
                                      std::istreambuf_iterator<char>());

        original_file.close();
        decrypted_file.close();

        runner.assert_equal(original_content, decrypted_content,
                            "File content should match after DEAL-192 encryption/decryption");
        runner.end_test(true);

    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_file_operations_deal_256(TestRunner& runner) {
    runner.start_test("File Operations with DEAL-256");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10},
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_256(key);

        SymmetricContext cipher(key, EncryptionModes::CBC, PaddingModes::PKCS7,
                                iv, {}, std::move(algorithm));

        std::filesystem::path base_dir = "tests\\test_deal\\src";
        std::filesystem::create_directories(base_dir);

        std::filesystem::path text_path = base_dir / "test_deal_256.txt";
        std::ofstream text_file(text_path);
        text_file << "DEAL-256 Test File Content\n";
        text_file << "This file tests DEAL-256 algorithm with 256-bit key\n";
        text_file << "Multiple lines to ensure proper encryption/decryption\n";
        text_file << "Additional line for larger file size testing\n";
        text_file.close();

        std::filesystem::path encrypted_path = base_dir / "encrypted_deal_256.bin";
        std::filesystem::path decrypted_path = base_dir / "decrypted_deal_256.txt";

        std::optional<std::filesystem::path> opt_encrypted = encrypted_path;
        cipher.encrypt(text_path, opt_encrypted).get();

        std::optional<std::filesystem::path> opt_decrypted = decrypted_path;
        cipher.decrypt(encrypted_path, opt_decrypted).get();

        std::ifstream original_file(text_path);
        std::ifstream decrypted_file(decrypted_path);

        std::string original_content((std::istreambuf_iterator<char>(original_file)),
                                     std::istreambuf_iterator<char>());
        std::string decrypted_content((std::istreambuf_iterator<char>(decrypted_file)),
                                      std::istreambuf_iterator<char>());

        original_file.close();
        decrypted_file.close();

        runner.assert_equal(original_content, decrypted_content,
                            "File content should match after DEAL-256 encryption/decryption");
        runner.end_test(true);

    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}
void test_text_file_operations_deal(TestRunner& runner) {
    runner.start_test("Text File Operations with DEAL-128");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_128(key);
        SymmetricContext cipher(key, EncryptionModes::CBC, PaddingModes::PKCS7, iv, {}, std::move(algorithm));

        std::filesystem::path base_dir = "tests\\test_deal\\src";
        std::filesystem::create_directories(base_dir);

        std::filesystem::path text_path;
        if (!test_config::text_file_path.empty()) {
            text_path = test_config::text_file_path;
            std::cout << "Using custom text file: " << text_path << std::endl;

            if (!std::filesystem::exists(text_path)) {
                std::cout << "✗ Custom text file not found: " << text_path << std::endl;
                runner.end_test(false);
                return;
            }
        } else {
            text_path = base_dir / "test_text_deal.txt";
            std::cout << "Creating test text file: " << text_path << std::endl;

            std::ofstream text_file(text_path);
            text_file << "This is a comprehensive test text file for DEAL encryption.\n";
            text_file << "Testing file size measurement and timing metrics for text files.\n";
            text_file << "Multiple lines to ensure proper encryption/decryption process.\n";
            text_file << "Final line of text content for complete testing coverage.";
            text_file.close();
        }

        std::filesystem::path encrypted_path = base_dir / "encrypted_text_deal.bin";
        std::filesystem::path decrypted_path = base_dir / "decrypted_text_deal.txt";

        auto encrypt_start = std::chrono::high_resolution_clock::now();
        std::optional<std::filesystem::path> opt_encrypted = encrypted_path;
        cipher.encrypt(text_path, opt_encrypted).get();
        auto encrypt_end = std::chrono::high_resolution_clock::now();
        auto encrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(encrypt_end - encrypt_start);

        auto decrypt_start = std::chrono::high_resolution_clock::now();
        std::optional<std::filesystem::path> opt_decrypted = decrypted_path;
        cipher.decrypt(encrypted_path, opt_decrypted).get();
        auto decrypt_end = std::chrono::high_resolution_clock::now();
        auto decrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(decrypt_end - decrypt_start);

        auto original_size = std::filesystem::file_size(text_path);
        auto encrypted_size = std::filesystem::file_size(encrypted_path);
        auto decrypted_size = std::filesystem::file_size(decrypted_path);

        print_file_metrics("Text File", original_size, encrypted_size, decrypted_size,
                           encrypt_duration, decrypt_duration);

        bool success = compare_files(text_path, decrypted_path);

        if (success) {
            std::cout << "Text file encryption/decryption successful - files match perfectly" << std::endl;
        } else {
            std::cout << "Text file encryption/decryption failed - file content mismatch" << std::endl;
        }

        runner.assert_true(success, "Text file content should match after DEAL encryption/decryption");
        runner.end_test(success);

    } catch (const std::exception& e) {
        std::cout << "Exception in text file test: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_binary_file_operations_deal(TestRunner& runner) {
    runner.start_test("Binary File Operations with DEAL-128");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_128(key);
        SymmetricContext cipher(key, EncryptionModes::CBC, PaddingModes::PKCS7, iv, {}, std::move(algorithm));

        std::filesystem::path base_dir = "tests\\test_deal\\src";
        std::filesystem::create_directories(base_dir);

        std::filesystem::path binary_path;
        if (!test_config::binary_file_path.empty()) {
            binary_path = test_config::binary_file_path;
            std::cout << "Using custom binary file: " << binary_path << std::endl;

            if (!std::filesystem::exists(binary_path)) {
                std::cout << "✗ Custom binary file not found: " << binary_path << std::endl;
                runner.end_test(false);
                return;
            }
        } else {
            binary_path = base_dir / "test_binary_deal.bin";
            std::cout << "Creating test binary file: " << binary_path << std::endl;

            std::ofstream binary_file(binary_path, std::ios::binary);

            std::vector<unsigned char> test_binary_data;
            for (size_t i = 0; i < 1 * 1024 * 1024; ++i) {
                test_binary_data.push_back(static_cast<unsigned char>((i * 7) % 256));
            }
            binary_file.write(reinterpret_cast<const char*>(test_binary_data.data()), test_binary_data.size());
            binary_file.close();
        }

        std::filesystem::path encrypted_path = base_dir / "encrypted_binary_deal.bin";
        std::filesystem::path decrypted_path = base_dir / "decrypted_binary_deal.bin";

        auto encrypt_start = std::chrono::high_resolution_clock::now();
        std::optional<std::filesystem::path> opt_encrypted = encrypted_path;
        cipher.encrypt(binary_path, opt_encrypted).get();
        auto encrypt_end = std::chrono::high_resolution_clock::now();
        auto encrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(encrypt_end - encrypt_start);

        auto decrypt_start = std::chrono::high_resolution_clock::now();
        std::optional<std::filesystem::path> opt_decrypted = decrypted_path;
        cipher.decrypt(encrypted_path, opt_decrypted).get();
        auto decrypt_end = std::chrono::high_resolution_clock::now();
        auto decrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(decrypt_end - decrypt_start);

        auto original_size = std::filesystem::file_size(binary_path);
        auto encrypted_size = std::filesystem::file_size(encrypted_path);
        auto decrypted_size = std::filesystem::file_size(decrypted_path);

        print_file_metrics("Binary File", original_size, encrypted_size, decrypted_size,
                           encrypt_duration, decrypt_duration);

        bool success = compare_files(binary_path, decrypted_path);

        if (success) {
            std::cout << "Binary file encryption/decryption successful - files match perfectly" << std::endl;
        } else {
            std::cout << "Binary file encryption/decryption failed - file content mismatch" << std::endl;
        }

        runner.assert_true(success, "Binary file content should match after DEAL encryption/decryption");
        runner.end_test(success);

    } catch (const std::exception& e) {
        std::cout << "Exception in binary file test: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_image_file_operations_deal(TestRunner& runner) {
    runner.start_test("Image File Operations with DEAL-128");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_128(key);
        SymmetricContext cipher(key, EncryptionModes::CBC, PaddingModes::PKCS7, iv, {}, std::move(algorithm));

        std::filesystem::path base_dir = "tests\\test_deal\\src";
        std::filesystem::create_directories(base_dir);

        std::filesystem::path image_path;
        if (!test_config::image_file_path.empty()) {
            image_path = test_config::image_file_path;
            std::cout << "Using custom image file: " << image_path << std::endl;

            if (!std::filesystem::exists(image_path)) {
                std::cout << "✗ Custom image file not found: " << image_path << std::endl;
                runner.end_test(false);
                return;
            }
        } else {
            image_path = base_dir / "test_image.jpg";
            std::cout << "Creating test image file: " << image_path << std::endl;

            std::ofstream image_file(image_path, std::ios::binary);
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

        std::filesystem::path encrypted_path = base_dir / "encrypted_image_deal.bin";
        std::filesystem::path decrypted_path = base_dir / "decrypted_image.jpg";

        auto encrypt_start = std::chrono::high_resolution_clock::now();
        std::optional<std::filesystem::path> opt_encrypted = encrypted_path;
        cipher.encrypt(image_path, opt_encrypted).get();
        auto encrypt_end = std::chrono::high_resolution_clock::now();
        auto encrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(encrypt_end - encrypt_start);

        auto decrypt_start = std::chrono::high_resolution_clock::now();
        std::optional<std::filesystem::path> opt_decrypted = decrypted_path;
        cipher.decrypt(encrypted_path, opt_decrypted).get();
        auto decrypt_end = std::chrono::high_resolution_clock::now();
        auto decrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(decrypt_end - decrypt_start);

        auto original_size = std::filesystem::file_size(image_path);
        auto encrypted_size = std::filesystem::file_size(encrypted_path);
        auto decrypted_size = std::filesystem::file_size(decrypted_path);

        print_file_metrics("Image File", original_size, encrypted_size, decrypted_size,
                           encrypt_duration, decrypt_duration);

        bool success = compare_files(image_path, decrypted_path);

        if (success) {
            std::cout << "Image file encryption/decryption successful - files match perfectly" << std::endl;
        } else {
            std::cout << "Image file encryption/decryption failed - file content mismatch" << std::endl;
        }

        runner.assert_true(success, "Image file content should match after DEAL encryption/decryption");
        runner.end_test(success);

    } catch (const std::exception& e) {
        std::cout << "Exception in image file test: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_pdf_file_operations_deal(TestRunner& runner) {
    runner.start_test("PDF File Operations with DEAL-128");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_128(key);
        SymmetricContext cipher(key, EncryptionModes::CBC, PaddingModes::PKCS7, iv, {}, std::move(algorithm));

        std::filesystem::path base_dir = "tests\\test_deal\\src";
        std::filesystem::create_directories(base_dir);

        std::filesystem::path pdf_path;
        if (!test_config::pdf_file_path.empty()) {
            pdf_path = test_config::pdf_file_path;
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

        std::filesystem::path encrypted_path = base_dir / "encrypted_pdf_deal.bin";
        std::filesystem::path decrypted_path = base_dir / "decrypted_document.pdf";

        auto encrypt_start = std::chrono::high_resolution_clock::now();
        std::optional<std::filesystem::path> opt_encrypted = encrypted_path;
        cipher.encrypt(pdf_path, opt_encrypted).get();
        auto encrypt_end = std::chrono::high_resolution_clock::now();
        auto encrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(encrypt_end - encrypt_start);

        auto decrypt_start = std::chrono::high_resolution_clock::now();
        std::optional<std::filesystem::path> opt_decrypted = decrypted_path;
        cipher.decrypt(encrypted_path, opt_decrypted).get();
        auto decrypt_end = std::chrono::high_resolution_clock::now();
        auto decrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(decrypt_end - decrypt_start);

        auto original_size = std::filesystem::file_size(pdf_path);
        auto encrypted_size = std::filesystem::file_size(encrypted_path);
        auto decrypted_size = std::filesystem::file_size(decrypted_path);

        print_file_metrics("PDF File", original_size, encrypted_size, decrypted_size,
                           encrypt_duration, decrypt_duration);

        bool success = compare_files(pdf_path, decrypted_path);

        if (success) {
            std::cout << "PDF file encryption/decryption successful - files match perfectly" << std::endl;
        } else {
            std::cout << "PDF file encryption/decryption failed - file content mismatch" << std::endl;
        }

        runner.assert_true(success, "PDF file content should match after DEAL encryption/decryption");
        runner.end_test(success);

    } catch (const std::exception& e) {
        std::cout << "Exception in PDF file test: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_zip_file_operations_deal(TestRunner& runner) {
    runner.start_test("ZIP File Operations with DEAL-128");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_128(key);
        SymmetricContext cipher(key, EncryptionModes::CBC, PaddingModes::PKCS7, iv, {}, std::move(algorithm));

        std::filesystem::path base_dir = "tests\\test_deal\\src";
        std::filesystem::create_directories(base_dir);

        std::filesystem::path zip_path;
        if (!test_config::zip_file_path.empty()) {
            zip_path = test_config::zip_file_path;
            std::cout << "Using custom ZIP file: " << zip_path << std::endl;

            if (!std::filesystem::exists(zip_path)) {
                std::cout << "✗ Custom ZIP file not found: " << zip_path << std::endl;
                runner.end_test(false);
                return;
            }
        } else {
            zip_path = base_dir / "test_archive.zip";
            std::cout << "Creating test ZIP file: " << zip_path << std::endl;

            std::ofstream zip_file(zip_path, std::ios::binary);

            const char* zip_content = "PK\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00";
            zip_file.write(zip_content, 12);

            for (int i = 0; i < 3; ++i) {
                std::string file_content = "This is test file " + std::to_string(i + 1) + " in ZIP archive.\n";
                file_content += "Contains sample data for encryption testing.\n";
                zip_file.write(file_content.c_str(), file_content.size());
            }

            zip_file.close();
        }

        std::filesystem::path encrypted_path = base_dir / "encrypted_zip_deal.bin";
        std::filesystem::path decrypted_path = base_dir / "decrypted_archive.zip";

        auto encrypt_start = std::chrono::high_resolution_clock::now();
        std::optional<std::filesystem::path> opt_encrypted = encrypted_path;
        cipher.encrypt(zip_path, opt_encrypted).get();
        auto encrypt_end = std::chrono::high_resolution_clock::now();
        auto encrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(encrypt_end - encrypt_start);

        auto decrypt_start = std::chrono::high_resolution_clock::now();
        std::optional<std::filesystem::path> opt_decrypted = decrypted_path;
        cipher.decrypt(encrypted_path, opt_decrypted).get();
        auto decrypt_end = std::chrono::high_resolution_clock::now();
        auto decrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(decrypt_end - decrypt_start);

        auto original_size = std::filesystem::file_size(zip_path);
        auto encrypted_size = std::filesystem::file_size(encrypted_path);
        auto decrypted_size = std::filesystem::file_size(decrypted_path);

        print_file_metrics("ZIP File", original_size, encrypted_size, decrypted_size,
                           encrypt_duration, decrypt_duration);

        bool success = compare_files(zip_path, decrypted_path);

        if (success) {
            std::cout << "ZIP file encryption/decryption successful - files match perfectly" << std::endl;
        } else {
            std::cout << "ZIP file encryption/decryption failed - file content mismatch" << std::endl;
        }

        runner.assert_true(success, "ZIP file content should match after DEAL encryption/decryption");
        runner.end_test(success);

    } catch (const std::exception& e) {
        std::cout << "Exception in ZIP file test: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void test_mp4_file_operations_deal(TestRunner& runner) {
    runner.start_test("MP4 File Operations with DEAL-128");

    try {
        std::vector<std::byte> key = {
                std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10}
        };

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
                std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
                std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm_128(key);
        SymmetricContext cipher(key, EncryptionModes::PCBC, PaddingModes::PKCS7, iv, {}, std::move(algorithm));

        std::filesystem::path base_dir = "tests\\test_deal\\src";
        std::filesystem::create_directories(base_dir);

        std::filesystem::path mp4_path;
        if (!test_config::mp4_file_path.empty()) {
            mp4_path = test_config::mp4_file_path;
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

            const char* fake_mp4_header = "ftypmp42";
            mp4_file.write(fake_mp4_header, 8);

            for (int frame = 0; frame < 100; ++frame) {
                std::string frame_data = "FRAME" + std::to_string(frame) + ":";
                for (int i = 0; i < 1024; ++i) {
                    frame_data += static_cast<char>((frame + i) % 256);
                }
                mp4_file.write(frame_data.c_str(), frame_data.size());
            }

            const char* fake_mp4_footer = "moov";
            mp4_file.write(fake_mp4_footer, 4);

            mp4_file.close();
        }

        std::filesystem::path encrypted_path = base_dir / "encrypted_mp4_deal.bin";
        std::filesystem::path decrypted_path = base_dir / "decrypted_video.mp4";

        auto encrypt_start = std::chrono::high_resolution_clock::now();
        std::optional<std::filesystem::path> opt_encrypted = encrypted_path;
        cipher.encrypt(mp4_path, opt_encrypted).get();
        auto encrypt_end = std::chrono::high_resolution_clock::now();
        auto encrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(encrypt_end - encrypt_start);

        auto decrypt_start = std::chrono::high_resolution_clock::now();
        std::optional<std::filesystem::path> opt_decrypted = decrypted_path;
        cipher.decrypt(encrypted_path, opt_decrypted).get();
        auto decrypt_end = std::chrono::high_resolution_clock::now();
        auto decrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(decrypt_end - decrypt_start);

        auto original_size = std::filesystem::file_size(mp4_path);
        auto encrypted_size = std::filesystem::file_size(encrypted_path);
        auto decrypted_size = std::filesystem::file_size(decrypted_path);

        print_file_metrics("MP4 File", original_size, encrypted_size, decrypted_size,
                           encrypt_duration, decrypt_duration);

        bool success = compare_files(mp4_path, decrypted_path);

        if (success) {
            std::cout << "MP4 file encryption/decryption successful - files match perfectly" << std::endl;
        } else {
            std::cout << "MP4 file encryption/decryption failed - file content mismatch" << std::endl;
        }

        runner.assert_true(success, "MP4 file content should match after DEAL encryption/decryption");
        runner.end_test(success);

    } catch (const std::exception& e) {
        std::cout << "Exception in MP4 file test: " << e.what() << std::endl;
        runner.end_test(false);
    }
}


int run_all_deal_tests() {
    TestRunner runner;

    std::cout << "Running DEAL Symmetric Algorithm Tests" << std::endl;
    std::cout << "======================================" << std::endl;

    try {
        /*test_ecb_encryption_decryption_deal(runner);
        test_cbc_encryption_decryption_deal(runner);
        test_pcbc_encryption_decryption_deal(runner);
        test_cfb_encryption_decryption_deal(runner);
        test_ofb_encryption_decryption_deal(runner);
        test_ctr_encryption_decryption_deal(runner);
        test_random_delta_encryption_decryption_deal(runner);
        test_different_padding_modes_deal(runner);
        test_empty_data_deal(runner);
        test_large_data_deal(runner);
        test_thread_safety_deal(runner);

        test_ecb_deal_192(runner);
        test_cbc_deal_192(runner);
        test_pcbc_deal_192(runner);
        test_cfb_deal_192(runner);
        test_ofb_deal_192(runner);
        test_ctr_deal_192(runner);
        test_random_delta_deal_192(runner);

        test_ecb_deal_256(runner);
        test_cbc_deal_256(runner);
        test_pcbc_deal_256(runner);
        test_cfb_deal_256(runner);
        test_ofb_deal_256(runner);
        test_ctr_deal_256(runner);
        test_random_delta_deal_256(runner);

        test_large_data_deal_192(runner);
        test_large_data_deal_256(runner);
        test_different_padding_modes_deal_192(runner);
        test_different_padding_modes_deal_256(runner);
        test_file_operations_deal_192(runner);
        test_file_operations_deal_256(runner);


        test_text_file_operations_deal(runner);
        test_binary_file_operations_deal(runner);
        test_image_file_operations_deal(runner);
        test_pdf_file_operations_deal(runner);
        test_zip_file_operations_deal(runner);*/
        test_mp4_file_operations_deal(runner);
    } catch (const std::exception& e) {
        std::cout << "DEAL Test interrupted by exception: " << e.what() << std::endl;
    }

    runner.print_summary();
    return runner.tests_failed > 0 ? 1 : 0;
}

void run_all_deal_tests_with_custom_files(
        const std::filesystem::path& text_file,
        const std::filesystem::path& binary_file,
        const std::filesystem::path& image_file,
        const std::filesystem::path& pdf_file,
        const std::filesystem::path& zip_file,
        const std::filesystem::path& mp4_file
) {
    test_config::set_custom_files(text_file, binary_file, image_file, pdf_file, zip_file, mp4_file);

    run_all_deal_tests();
}
