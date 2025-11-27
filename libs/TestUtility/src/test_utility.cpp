#include "test_utility.hpp"

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

void TestFileConfig::set_custom_files(
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
}

void TestFileConfig::print_available_files() const {
    std::cout << "Available test files:" << std::endl;
    if (!text_file_path.empty() && std::filesystem::exists(text_file_path))
        std::cout << "  Text: " << text_file_path << " (" << std::filesystem::file_size(text_file_path) << " bytes)" << std::endl;
    if (!binary_file_path.empty() && std::filesystem::exists(binary_file_path))
        std::cout << "  Binary: " << binary_file_path << " (" << std::filesystem::file_size(binary_file_path) << " bytes)" << std::endl;
    if (!image_file_path.empty() && std::filesystem::exists(image_file_path))
        std::cout << "  Image: " << image_file_path << " (" << std::filesystem::file_size(image_file_path) << " bytes)" << std::endl;
    if (!pdf_file_path.empty() && std::filesystem::exists(pdf_file_path))
        std::cout << "  PDF: " << pdf_file_path << " (" << std::filesystem::file_size(pdf_file_path) << " bytes)" << std::endl;
    if (!zip_file_path.empty() && std::filesystem::exists(zip_file_path))
        std::cout << "  ZIP: " << zip_file_path << " (" << std::filesystem::file_size(zip_file_path) << " bytes)" << std::endl;
    if (!mp4_file_path.empty() && std::filesystem::exists(mp4_file_path))
        std::cout << "  MP4: " << mp4_file_path << " (" << std::filesystem::file_size(mp4_file_path) << " bytes)" << std::endl;
}

namespace test_utils {
    std::filesystem::path setup_test_directory(const std::string& algorithm_name) {
        if (algorithm_name.find("DEAL") != std::string::npos) {
            std::filesystem::path base_dir = "tests/test_deal/results";
            std::filesystem::create_directories(base_dir);
            return base_dir;
        }
        if (algorithm_name.find("TripleDES") != std::string::npos) {
            std::filesystem::path base_dir = "tests/test_triple_des/result";
            std::filesystem::create_directories(base_dir);
            return base_dir;
        }
        std::filesystem::path base_dir = "tests/test_" + algorithm_name + "/results";
        std::filesystem::create_directories(base_dir);
        return base_dir;
    }

    bool test_single_file_operation(
            TestRunner& runner,
            const std::string& file_type,
            const std::filesystem::path& file_path,
            const std::vector<std::byte>& key,
            const std::vector<std::byte>& iv,
            std::unique_ptr<symmetric_context::SymmetricAlgorithm> algorithm,
            symmetric_context::EncryptionModes encryption_mode,
            symmetric_context::PaddingModes padding_mode,
            const std::string& algorithm_name
    ) {
        if (!std::filesystem::exists(file_path)) {
            std::cout << "File not found: " << file_path << std::endl;
            return false;
        }

        try {
            auto base_dir = setup_test_directory(algorithm_name);
            symmetric_context::SymmetricContext cipher(
                    key, encryption_mode, padding_mode, iv, {}, std::move(algorithm)
            );

            std::string file_stem = file_path.stem().string();
            std::filesystem::path encrypted_path = base_dir / (file_stem + "_encrypted_" + algorithm_name + file_path.extension().string());
            std::filesystem::path decrypted_path = base_dir / (file_stem + "_decrypted_" + algorithm_name + file_path.extension().string());

            std::cout << "Testing " << file_type << " file: " << file_path.filename() << std::endl;
            std::cout << "  Original: " << file_path << std::endl;
            std::cout << "  Encrypted: " << encrypted_path << std::endl;
            std::cout << "  Decrypted: " << decrypted_path << std::endl;

            auto encrypt_start = std::chrono::high_resolution_clock::now();
            std::optional<std::filesystem::path> opt_encrypted = encrypted_path;
            cipher.encrypt(file_path, opt_encrypted).get();
            auto encrypt_end = std::chrono::high_resolution_clock::now();
            auto encrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(encrypt_end - encrypt_start);

            auto decrypt_start = std::chrono::high_resolution_clock::now();
            std::optional<std::filesystem::path> opt_decrypted = decrypted_path;
            cipher.decrypt(encrypted_path, opt_decrypted).get();
            auto decrypt_end = std::chrono::high_resolution_clock::now();
            auto decrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(decrypt_end - decrypt_start);

            auto original_size = std::filesystem::file_size(file_path);
            auto encrypted_size = std::filesystem::file_size(encrypted_path);
            auto decrypted_size = std::filesystem::file_size(decrypted_path);

            print_file_metrics(file_type + " File", original_size, encrypted_size, decrypted_size,
                               encrypt_duration, decrypt_duration);

            bool success = compare_files(file_path, decrypted_path);

            if (success) {
                std::cout << file_type << " file encryption/decryption successful" << std::endl;
            } else {
                std::cout <<  file_type << " file encryption/decryption failed" << std::endl;
            }

            return success;

        } catch (const std::exception& e) {
            std::cout << "Exception in " << file_type << " file test: " << e.what() << std::endl;
            return false;
        }
    }
}

void AlgorithmTestBase::test_basic_encryption_modes(
        const std::vector<std::byte>& key,
        const std::vector<std::byte>& iv,
        std::unique_ptr<symmetric_context::SymmetricAlgorithm> (*create_algorithm)(const std::vector<std::byte>&),
        const std::string& algorithm_name
) {
    std::vector<symmetric_context::EncryptionModes> modes = {
            symmetric_context::EncryptionModes::ECB,
            symmetric_context::EncryptionModes::CBC,
            symmetric_context::EncryptionModes::PCBC,
            symmetric_context::EncryptionModes::CFB,
            symmetric_context::EncryptionModes::OFB,
            symmetric_context::EncryptionModes::CTR,
            symmetric_context::EncryptionModes::RandomDelta
    };

    std::vector<std::byte> test_data = {
            std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
            std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}
    };

    for (auto mode : modes) {
        std::string mode_name;
        switch (mode) {
            case symmetric_context::EncryptionModes::ECB: mode_name = "ECB"; break;
            case symmetric_context::EncryptionModes::CBC: mode_name = "CBC"; break;
            case symmetric_context::EncryptionModes::PCBC: mode_name = "PCBC"; break;
            case symmetric_context::EncryptionModes::CFB: mode_name = "CFB"; break;
            case symmetric_context::EncryptionModes::OFB: mode_name = "OFB"; break;
            case symmetric_context::EncryptionModes::CTR: mode_name = "CTR"; break;
            case symmetric_context::EncryptionModes::RandomDelta: mode_name = "RandomDelta"; break;
        }

        runner.start_test(mode_name + " Encryption/Decryption with " + algorithm_name);

        try {
            auto algorithm = create_algorithm(key);
            std::optional<std::vector<std::byte>> opt_iv = (mode != symmetric_context::EncryptionModes::ECB)
                                                           ? std::make_optional(iv) : std::nullopt;

            symmetric_context::SymmetricContext algo(key, mode, symmetric_context::PaddingModes::PKCS7,
                                                     opt_iv, {}, std::move(algorithm));

            auto encrypted = algo.encrypt(test_data).get();
            auto decrypted = algo.decrypt(encrypted).get();

            runner.assert_true(compare_byte_vectors(test_data, decrypted),
                               mode_name + " with " + algorithm_name + ": Original and decrypted data should match");
            runner.end_test(true);
        } catch (const std::exception& e) {
            std::cout << "Exception: " << e.what() << std::endl;
            runner.end_test(false);
        }
    }
}

void AlgorithmTestBase::test_file_operations(
        const std::vector<std::byte>& key,
        const std::vector<std::byte>& iv,
        std::unique_ptr<symmetric_context::SymmetricAlgorithm> (*create_algorithm)(const std::vector<std::byte>&),
        const TestFileConfig& config,
        const std::string& algorithm_name
) {
    if (!config.has_any_files()) {
        std::cout << "No test files provided - skipping file operations tests" << std::endl;
        return;
    }

    config.print_available_files();
    std::cout << std::endl;

    std::vector<std::pair<std::string, std::filesystem::path>> test_files = {
            {"Text", config.text_file_path},
            {"Binary", config.binary_file_path},
            {"Image", config.image_file_path},
            {"PDF", config.pdf_file_path},
            {"ZIP", config.zip_file_path},
            {"MP4", config.mp4_file_path}
    };

    for (const auto& [file_type, file_path] : test_files) {
        if (file_path.empty()) {
            continue;
        }

        runner.start_test(file_type + " File Operations with " + algorithm_name);

        auto algorithm = create_algorithm(key);
        bool success = test_utils::test_single_file_operation(
                runner, file_type, file_path, key, iv,
                std::move(algorithm), get_file_encryption_mode(),
                get_file_padding_mode(), algorithm_name
        );

        runner.assert_true(success, file_type + " file content should match after " + algorithm_name + " encryption/decryption");
        runner.end_test(success);
    }
}

void AlgorithmTestBase::test_padding_modes(
        const std::vector<std::byte>& key,
        const std::vector<std::byte>& iv,
        std::unique_ptr<symmetric_context::SymmetricAlgorithm> (*create_algorithm)(const std::vector<std::byte>&)
) {
    runner.start_test("Different Padding Modes");

    std::vector<std::vector<std::byte>> test_data_sets = {
            {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}},
            {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                    std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}},
            {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                    std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                    std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}}
    };

    std::vector<symmetric_context::PaddingModes> padding_modes = {
            symmetric_context::PaddingModes::ANSIX_923,
            symmetric_context::PaddingModes::PKCS7,
            symmetric_context::PaddingModes::ISO_10126
    };

    bool all_passed = true;

    for (auto padding_mode : padding_modes) {
        for (const auto& test_data : test_data_sets) {
            try {
                auto algorithm = create_algorithm(key);
                symmetric_context::SymmetricContext algo(key, symmetric_context::EncryptionModes::CBC, padding_mode,
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

    runner.assert_true(all_passed, "All padding modes should work correctly");
    runner.end_test(all_passed);
}

void AlgorithmTestBase::test_edge_cases(
        const std::vector<std::byte>& key,
        std::unique_ptr<symmetric_context::SymmetricAlgorithm> (*create_algorithm)(const std::vector<std::byte>&)
) {
    runner.start_test("Empty Data Handling");
    try {
        std::vector<std::byte> empty_data;
        auto algorithm = create_algorithm(key);
        symmetric_context::SymmetricContext algo(key, symmetric_context::EncryptionModes::ECB,
                                                 symmetric_context::PaddingModes::PKCS7,
                                                 std::nullopt, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(empty_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        runner.assert_true(decrypted.empty(), "Empty data should remain empty after encryption/decryption");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }

    runner.start_test("Large Data Handling");
    try {
        std::vector<std::byte> large_data;
        for (int i = 0; i < 64; ++i) {
            large_data.push_back(static_cast<std::byte>(0x20 + i));
        }

        std::vector<std::byte> iv = {
                std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
                std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22}
        };

        auto algorithm = create_algorithm(key);
        symmetric_context::SymmetricContext algo(key, symmetric_context::EncryptionModes::CBC,
                                                 symmetric_context::PaddingModes::PKCS7,
                                                 iv, {}, std::move(algorithm));

        auto encrypted = algo.encrypt(large_data).get();
        auto decrypted = algo.decrypt(encrypted).get();

        bool data_matches = compare_byte_vectors(large_data, decrypted);
        runner.assert_true(data_matches && large_data.size() == decrypted.size(),
                           "Large data should be correctly encrypted and decrypted");
        runner.end_test(data_matches && large_data.size() == decrypted.size());
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}