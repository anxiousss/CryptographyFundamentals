#include "test_rijndael.hpp"
#include <iostream>
#include <chrono>
#include <random>
#include <cassert>
#include <filesystem>



std::byte get_aes_polynomial() {
    return std::byte{0x1B};
}

void safe_initialize_galois() {
    static bool initialized = false;
    if (!initialized) {
        try {
            std::byte a{0x01};
            std::byte b{0x02};
            auto result = galois_fields::GaloisField::add(a, b);
            initialized = true;
        } catch (...) {
            initialized = true;
        }
    }
}

std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_rijndael_128_128(const std::vector<std::byte>& key) {
    if (key.size() != 16) {
        throw std::invalid_argument("Key size must be 16 bytes for AES-128");
    }

    safe_initialize_galois();
    std::vector<std::byte> key_copy = key;

    try {
        return std::make_unique<rijndael::Rijndael>(key_copy, 16, get_aes_polynomial());
    } catch (const std::exception& e) {
        std::cerr << "Error creating Rijndael 128-128: " << e.what() << std::endl;
        throw;
    }
}

std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_rijndael_192_128(const std::vector<std::byte>& key) {
    if (key.size() != 24) {
        throw std::invalid_argument("Key size must be 24 bytes for AES-192");
    }

    safe_initialize_galois();
    std::vector<std::byte> key_copy = key;

    try {
        return std::make_unique<rijndael::Rijndael>(key_copy, 16, get_aes_polynomial());
    } catch (const std::exception& e) {
        std::cerr << "Error creating Rijndael 192-128: " << e.what() << std::endl;
        throw;
    }
}

std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_rijndael_256_128(const std::vector<std::byte>& key) {
    if (key.size() != 32) {
        throw std::invalid_argument("Key size must be 32 bytes for AES-256");
    }

    safe_initialize_galois();
    std::vector<std::byte> key_copy = key;

    try {
        return std::make_unique<rijndael::Rijndael>(key_copy, 16, get_aes_polynomial());
    } catch (const std::exception& e) {
        std::cerr << "Error creating Rijndael 256-128: " << e.what() << std::endl;
        throw;
    }
}

std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_rijndael_128_192(const std::vector<std::byte>& key) {
    if (key.size() != 16) {
        throw std::invalid_argument("Key size must be 16 bytes for Rijndael-128-192");
    }

    safe_initialize_galois();
    std::vector<std::byte> key_copy = key;

    try {
        return std::make_unique<rijndael::Rijndael>(key_copy, 24, get_aes_polynomial());
    } catch (const std::exception& e) {
        std::cerr << "Error creating Rijndael 128-192: " << e.what() << std::endl;
        throw;
    }
}

std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_rijndael_192_192(const std::vector<std::byte>& key) {
    if (key.size() != 24) {
        throw std::invalid_argument("Key size must be 24 bytes for Rijndael-192-192");
    }

    safe_initialize_galois();
    std::vector<std::byte> key_copy = key;

    try {
        return std::make_unique<rijndael::Rijndael>(key_copy, 24, get_aes_polynomial());
    } catch (const std::exception& e) {
        std::cerr << "Error creating Rijndael 192-192: " << e.what() << std::endl;
        throw;
    }
}

std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_rijndael_256_192(const std::vector<std::byte>& key) {
    if (key.size() != 32) {
        throw std::invalid_argument("Key size must be 32 bytes for Rijndael-256-192");
    }

    safe_initialize_galois();
    std::vector<std::byte> key_copy = key;

    try {
        return std::make_unique<rijndael::Rijndael>(key_copy, 24, get_aes_polynomial());
    } catch (const std::exception& e) {
        std::cerr << "Error creating Rijndael 256-192: " << e.what() << std::endl;
        throw;
    }
}

std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_rijndael_128_256(const std::vector<std::byte>& key) {
    if (key.size() != 16) {
        throw std::invalid_argument("Key size must be 16 bytes for Rijndael-128-256");
    }

    safe_initialize_galois();
    std::vector<std::byte> key_copy = key;

    try {
        return std::make_unique<rijndael::Rijndael>(key_copy, 32, get_aes_polynomial());
    } catch (const std::exception& e) {
        std::cerr << "Error creating Rijndael 128-256: " << e.what() << std::endl;
        throw;
    }
}

std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_rijndael_192_256(const std::vector<std::byte>& key) {
    if (key.size() != 24) {
        throw std::invalid_argument("Key size must be 24 bytes for Rijndael-192-256");
    }

    safe_initialize_galois();
    std::vector<std::byte> key_copy = key;

    try {
        return std::make_unique<rijndael::Rijndael>(key_copy, 32, get_aes_polynomial());
    } catch (const std::exception& e) {
        std::cerr << "Error creating Rijndael 192-256: " << e.what() << std::endl;
        throw;
    }
}

std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_rijndael_256_256(const std::vector<std::byte>& key) {
    if (key.size() != 32) {
        throw std::invalid_argument("Key size must be 32 bytes for Rijndael-256-256");
    }

    safe_initialize_galois();
    std::vector<std::byte> key_copy = key;

    try {
        return std::make_unique<rijndael::Rijndael>(key_copy, 32, get_aes_polynomial());
    } catch (const std::exception& e) {
        std::cerr << "Error creating Rijndael 256-256: " << e.what() << std::endl;
        throw;
    }
}

std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_aes_128(const std::vector<std::byte>& key) {
    return create_rijndael_128_128(key);
}

std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_aes_192(const std::vector<std::byte>& key) {
    return create_rijndael_192_128(key);
}

std::unique_ptr<symmetric_context::SymmetricAlgorithm> create_aes_256(const std::vector<std::byte>& key) {
    return create_rijndael_256_128(key);
}



void RijndaelTest::initialize_galois_fields() {
    safe_initialize_galois();
}

std::filesystem::path RijndaelTest::setup_test_directory() {
    std::filesystem::path base_dir = "test_rijndael/results";
    std::filesystem::create_directories(base_dir);
    return base_dir;
}

bool test_rijndael_file_operation(
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
        symmetric_context::SymmetricContext cipher(
                key, encryption_mode, padding_mode, iv, {}, std::move(algorithm)
        );

        std::string file_stem = file_path.stem().string();
        std::filesystem::path results_dir = "tests/test_rijndael/results";
        std::filesystem::create_directories(results_dir);

        std::filesystem::path encrypted_path = results_dir / (file_stem + "_" + algorithm_name + "_encrypted" + file_path.extension().string());
        std::filesystem::path decrypted_path = results_dir / (file_stem + "_" + algorithm_name + "_decrypted" + file_path.extension().string());

        std::cout << "Testing " << file_type << " file with " << algorithm_name << ":" << std::endl;
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

        print_file_metrics(file_type + " File (" + algorithm_name + ")",
                           original_size, encrypted_size, decrypted_size,
                           encrypt_duration, decrypt_duration);

        bool success = compare_files(file_path, decrypted_path);

        if (success) {
            std::cout << "✓ " << file_type << " file encryption/decryption successful with " << algorithm_name << std::endl;
        } else {
            std::cout << "✗ " << file_type << " file encryption/decryption failed with " << algorithm_name << std::endl;
        }

        return success;

    } catch (const std::exception& e) {
        std::cout << "Exception in " << file_type << " file test (" << algorithm_name << "): " << e.what() << std::endl;
        return false;
    }
}

void RijndaelTest::test_aes_128(const TestFileConfig& config) {
    std::cout << "\n--- Testing AES-128 (128-bit key, 128-bit block) ---" << std::endl;

    std::vector<std::byte> key(16);
    for (size_t i = 0; i < 16; ++i) {
        key[i] = static_cast<std::byte>(i + 1);
    }

    std::vector<std::byte> iv(16);
    for (size_t i = 0; i < 16; ++i) {
        iv[i] = static_cast<std::byte>(i + 0x10);
    }

    test_basic_encryption_modes(key, iv, create_aes_128, "AES-128");

    if (config.has_any_files()) {
        std::vector<std::pair<std::string, std::filesystem::path>> test_files = {
                {"Text", config.text_file_path},
                {"Binary", config.binary_file_path},
                {"Image", config.image_file_path},
                {"PDF", config.pdf_file_path},
                {"ZIP", config.zip_file_path},
                {"MP4", config.mp4_file_path}
        };

        for (const auto& [file_type, file_path] : test_files) {
            if (!file_path.empty() && std::filesystem::exists(file_path)) {
                runner.start_test("AES-128 " + file_type + " File");
                auto algorithm = create_aes_128(key);
                bool success = test_rijndael_file_operation(
                        runner, file_type, file_path, key, iv,
                        std::move(algorithm), get_file_encryption_mode(),
                        get_file_padding_mode(), "AES-128"
                );
                runner.assert_true(success, "AES-128 " + file_type + " file should be correctly processed");
                runner.end_test(success);
            }
        }
    }


    test_padding_modes(key, iv, create_aes_128);
    test_edge_cases(key, create_aes_128);
}

void RijndaelTest::test_aes_192(const TestFileConfig& config) {
    std::cout << "\n--- Testing AES-192 (192-bit key, 128-bit block) ---" << std::endl;

    std::vector<std::byte> key(24);
    for (size_t i = 0; i < 24; ++i) {
        key[i] = static_cast<std::byte>(i + 0x20);
    }

    std::vector<std::byte> iv(16);
    for (size_t i = 0; i < 16; ++i) {
        iv[i] = static_cast<std::byte>(i + 0x30);
    }

    test_basic_encryption_modes(key, iv, create_aes_192, "AES-192");

    if (config.has_any_files()) {
        if (!config.text_file_path.empty() && std::filesystem::exists(config.text_file_path)) {
            runner.start_test("AES-192 Text File");
            auto algorithm = create_aes_192(key);
            bool success = test_rijndael_file_operation(
                    runner, "Text", config.text_file_path, key, iv,
                    std::move(algorithm), get_file_encryption_mode(),
                    get_file_padding_mode(), "AES-192"
            );
            runner.assert_true(success, "AES-192 text file should be correctly processed");
            runner.end_test(success);
        }
    }

    test_padding_modes(key, iv, create_aes_192);
    test_edge_cases(key, create_aes_192);
}

void RijndaelTest::test_aes_256(const TestFileConfig& config) {
    std::cout << "\n--- Testing AES-256 (256-bit key, 128-bit block) ---" << std::endl;

    std::vector<std::byte> key(32);
    for (size_t i = 0; i < 32; ++i) {
        key[i] = static_cast<std::byte>(i + 0x40);
    }

    std::vector<std::byte> iv(16);
    for (size_t i = 0; i < 16; ++i) {
        iv[i] = static_cast<std::byte>(i + 0x50);
    }

    test_basic_encryption_modes(key, iv, create_aes_256, "AES-256");

    if (config.has_any_files()) {
        if (!config.text_file_path.empty() && std::filesystem::exists(config.text_file_path)) {
            runner.start_test("AES-256 Text File");
            auto algorithm = create_aes_256(key);
            bool success = test_rijndael_file_operation(
                    runner, "Text", config.text_file_path, key, iv,
                    std::move(algorithm), get_file_encryption_mode(),
                    get_file_padding_mode(), "AES-256"
            );
            runner.assert_true(success, "AES-256 text file should be correctly processed");
            runner.end_test(success);
        }
    }

    test_padding_modes(key, iv, create_aes_256);
    test_edge_cases(key, create_aes_256);
}

void RijndaelTest::test_rijndael_192_block(const TestFileConfig& config) {
    std::cout << "\n--- Testing Rijndael with 192-bit block ---" << std::endl;

    std::vector<std::byte> key(16);
    for (size_t i = 0; i < 16; ++i) {
        key[i] = static_cast<std::byte>(i + 0x60);
    }

    std::vector<std::byte> iv(24);
    for (size_t i = 0; i < 24; ++i) {
        iv[i] = static_cast<std::byte>(i + 0x70);
    }

    test_basic_encryption_modes(key, iv, create_rijndael_128_192, "Rijndael-192-block");

    if (config.has_any_files()) {
        if (!config.text_file_path.empty() && std::filesystem::exists(config.text_file_path)) {
            runner.start_test("Rijndael-192-block Text File");
            auto algorithm = create_rijndael_128_192(key);
            bool success = test_rijndael_file_operation(
                    runner, "Text", config.text_file_path, key, iv,
                    std::move(algorithm), get_file_encryption_mode(),
                    get_file_padding_mode(), "Rijndael-192"
            );
            runner.assert_true(success, "Rijndael 192-bit block text file should be correctly processed");
            runner.end_test(success);
        }
    }
}

void RijndaelTest::test_rijndael_256_block(const TestFileConfig& config) {
    std::cout << "\n--- Testing Rijndael with 256-bit block ---" << std::endl;

    std::vector<std::byte> key(16);
    for (size_t i = 0; i < 16; ++i) {
        key[i] = static_cast<std::byte>(i + 0x80);
    }

    std::vector<std::byte> iv(32);
    for (size_t i = 0; i < 32; ++i) {
        iv[i] = static_cast<std::byte>(i + 0x90);
    }

    test_basic_encryption_modes(key, iv, create_rijndael_128_256, "Rijndael-256-block");

    if (config.has_any_files()) {
        if (!config.text_file_path.empty() && std::filesystem::exists(config.text_file_path)) {
            runner.start_test("Rijndael-256-block Text File");
            auto algorithm = create_rijndael_128_256(key);
            bool success = test_rijndael_file_operation(
                    runner, "Text", config.text_file_path, key, iv,
                    std::move(algorithm), get_file_encryption_mode(),
                    get_file_padding_mode(), "Rijndael-256"
            );
            runner.assert_true(success, "Rijndael 256-bit block text file should be correctly processed");
            runner.end_test(success);
        }
    }
}

void RijndaelTest::run_all_rijndael_tests(const TestFileConfig& config) {
    std::cout << "\n=== RUNNING RIJNDAEL (AES) TESTS ===" << std::endl;
    std::cout << "Results will be saved in: test_rijndael/results/" << std::endl;

    std::filesystem::create_directories("tests/test_rijndael/results");

    initialize_galois_fields();

    runner.start_test("Basic Rijndael Algorithm Creation");
    try {
        std::vector<std::byte> test_key(16, std::byte{0x01});
        auto algo = create_aes_128(test_key);

        std::vector<std::byte> test_block(16, std::byte{0x00});
        auto encrypted = algo->encrypt(test_block);
        auto decrypted = algo->decrypt(encrypted);

        runner.assert_true(encrypted.size() == test_block.size(),
                           "Encrypted block should have same size as input");
        runner.assert_true(decrypted.size() == test_block.size(),
                           "Decrypted block should have same size as input");
        runner.assert_true(!compare_byte_vectors(test_block, encrypted),
                           "Encrypted data should be different from original");
        runner.assert_true(compare_byte_vectors(test_block, decrypted),
                           "Decrypted data should match original");

        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception in basic test: " << e.what() << std::endl;
        runner.end_test(false);
        return;
    }

    test_aes_128(config);
//    test_aes_192(config);
//    test_aes_256(config);
//
//    // Тесты с нестандартными размерами блоков
//    if (config.has_any_files()) {
//        test_rijndael_192_block(config);
//        test_rijndael_256_block(config);
//    }

    runner.start_test("Random Key/IV Test");
    try {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);

        std::vector<std::byte> random_key(16);
        for (auto& b : random_key) b = static_cast<std::byte>(dis(gen));

        std::vector<std::byte> random_iv(16);
        for (auto& b : random_iv) b = static_cast<std::byte>(dis(gen));

        std::vector<std::byte> test_data(64);
        for (auto& b : test_data) b = static_cast<std::byte>(dis(gen));

        auto algo = create_aes_128(random_key);
        symmetric_context::SymmetricContext ctx(random_key,
                                                symmetric_context::EncryptionModes::CBC,
                                                symmetric_context::PaddingModes::PKCS7,
                                                random_iv, {}, std::move(algo));

        auto encrypted = ctx.encrypt(test_data).get();
        auto decrypted = ctx.decrypt(encrypted).get();

        runner.assert_true(compare_byte_vectors(test_data, decrypted),
                           "Encryption/decryption with random key/IV should work");
        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}



void run_all_rijndael_tests_with_custom_files(
        const std::filesystem::path& text_file,
        const std::filesystem::path& binary_file,
        const std::filesystem::path& image_file,
        const std::filesystem::path& pdf_file,
        const std::filesystem::path& zip_file,
        const std::filesystem::path& mp4_file) {

    std::cout << "=== RIJNDAEL/AES TEST SUITE ===" << std::endl;
    std::cout << "==============================" << std::endl;

    TestFileConfig config;
    config.set_custom_files(text_file, binary_file, image_file, pdf_file, zip_file, mp4_file);

    if (config.has_any_files()) {
        std::cout << "\nTest files found:" << std::endl;
        config.print_available_files();
    } else {
        std::cout << "\nNo test files provided. Running basic encryption tests only." << std::endl;
    }

    TestRunner runner;
    RijndaelTest rijndael_test(runner);

    auto start_time = std::chrono::high_resolution_clock::now();

    try {
        rijndael_test.run_all_rijndael_tests(config);
    } catch (const std::exception& e) {
        std::cerr << "\nFatal error in Rijndael tests: " << e.what() << std::endl;
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    std::cout << "\n=== RIJNDAEL TESTS COMPLETED ===" << std::endl;
    std::cout << "Total time: " << duration.count() << " ms" << std::endl;
    std::cout << "Results saved in: test_rijndael/results/" << std::endl;

    runner.print_summary();
}

void run_basic_rijndael_tests() {
    std::cout << "=== BASIC RIJNDAEL/AES TESTS (NO FILES) ===" << std::endl;
    std::cout << "=========================================" << std::endl;

    TestRunner runner;
    RijndaelTest rijndael_test(runner);

    TestFileConfig config;

    auto start_time = std::chrono::high_resolution_clock::now();

    try {
        rijndael_test.run_all_rijndael_tests(config);
    } catch (const std::exception& e) {
        std::cerr << "\nFatal error in basic Rijndael tests: " << e.what() << std::endl;
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    std::cout << "\n=== BASIC RIJNDAEL TESTS COMPLETED ===" << std::endl;
    std::cout << "Total time: " << duration.count() << " ms" << std::endl;

    runner.print_summary();
}