#include "test_triple_des.hpp"
#include <iomanip>

std::unique_ptr<symmetric_context::SymmetricAlgorithm> TripleDESTest::create_tripledes_algorithm_ede(const std::vector<std::byte>& key) {
    return std::make_unique<triple_des::TripleDes>(triple_des::AlgorithmType::EDE, key);
}

std::unique_ptr<symmetric_context::SymmetricAlgorithm> TripleDESTest::create_tripledes_algorithm_eee(const std::vector<std::byte>& key) {
    return std::make_unique<triple_des::TripleDes>(triple_des::AlgorithmType::EEE, key);
}

void TripleDESTest::run_all_tests(const TestFileConfig& config) {
    std::cout << "Running TripleDES Symmetric Algorithm Tests" << std::endl;
    std::cout << "===========================================" << std::endl;

    test_single_block_operations();

    std::cout << "\n--- Triple-DES EDE Mode Tests ---" << std::endl;
    test_basic_encryption_modes(get_default_key(), get_default_iv(), create_tripledes_algorithm_ede, "TripleDES-EDE");
    test_padding_modes(get_default_key(), get_default_iv(), create_tripledes_algorithm_ede);
    test_edge_cases(get_default_key(), create_tripledes_algorithm_ede);

    std::cout << "\n--- Triple-DES EEE Mode Tests ---" << std::endl;
    test_basic_encryption_modes(get_default_key(), get_default_iv(), create_tripledes_algorithm_eee, "TripleDES-EEE");
    test_padding_modes(get_default_key(), get_default_iv(), create_tripledes_algorithm_eee);
    test_edge_cases(get_default_key(), create_tripledes_algorithm_eee);

    test_thread_safety();
    test_performance();

    if (config.has_any_files()) {
        std::cout << "\n--- Triple-DES File Operations ---" << std::endl;
        test_file_operations(get_default_key(), get_default_iv(), create_tripledes_algorithm_ede, config, "TripleDES-EDE");
        test_file_operations(get_default_key(), get_default_iv(), create_tripledes_algorithm_eee, config, "TripleDES-EEE");
    }
}

void TripleDESTest::test_single_block_operations() {
    std::cout << "\n--- Testing Single Block Operations ---" << std::endl;

    auto key = get_default_key();

    std::vector<std::byte> test_block = {
            std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
            std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF}
    };

    runner.start_test("Single Block EDE Encryption/Decryption");
    try {
        auto algorithm_ede = create_tripledes_algorithm_ede(key);
        auto encrypted = algorithm_ede->encrypt(test_block);
        auto decrypted = algorithm_ede->decrypt(encrypted);
        bool success = compare_byte_vectors(test_block, decrypted);

        runner.assert_true(success, "Single block EDE should work correctly");
        runner.end_test(success);
    } catch (const std::exception& e) {
        std::cout << "Exception in EDE test: " << e.what() << std::endl;
        runner.end_test(false);
    }

    runner.start_test("Single Block EEE Encryption/Decryption");
    try {
        auto algorithm_eee = create_tripledes_algorithm_eee(key);

        auto encrypted = algorithm_eee->encrypt(test_block);
        auto decrypted = algorithm_eee->decrypt(encrypted);

        bool success = compare_byte_vectors(test_block, decrypted);
        runner.assert_true(success, "Single block EEE should work correctly");
        runner.end_test(success);
    } catch (const std::exception& e) {
        std::cout << "Exception in EEE test: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

std::vector<std::byte> TripleDESTest::get_default_key() const {
    return {
            std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
            std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
            std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
            std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10},
            std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
            std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67}
    };
}

std::vector<std::byte> TripleDESTest::get_default_iv() const {
    return {
            std::byte{0x12}, std::byte{0x34}, std::byte{0x56}, std::byte{0x78},
            std::byte{0x90}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF}
    };
}

void TripleDESTest::test_thread_safety() {
    runner.start_test("Thread Safety with TripleDES");

    try {
        auto key = get_default_key();
        auto iv = get_default_iv();

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}
        };

        auto algorithm_ede = create_tripledes_algorithm_ede(key);
        symmetric_context::SymmetricContext algo_ede(key, symmetric_context::EncryptionModes::CFB,
                                                     symmetric_context::PaddingModes::PKCS7, iv, {}, std::move(algorithm_ede));

        bool thread_safe_ede = true;

        auto encrypt_task1_ede = algo_ede.encrypt(test_data);
        auto encrypt_task2_ede = algo_ede.encrypt(test_data);

        auto encrypted1_ede = encrypt_task1_ede.get();
        auto encrypted2_ede = encrypt_task2_ede.get();

        auto final_decrypted_ede = algo_ede.decrypt(encrypted1_ede).get();
        if (!compare_byte_vectors(test_data, final_decrypted_ede)) {
            thread_safe_ede = false;
            std::cout << "Thread safety check failed for EDE - decrypted data doesn't match original" << std::endl;
        }

        auto algorithm_eee = create_tripledes_algorithm_eee(key);
        symmetric_context::SymmetricContext algo_eee(key, symmetric_context::EncryptionModes::CFB,
                                                     symmetric_context::PaddingModes::PKCS7, iv, {}, std::move(algorithm_eee));

        bool thread_safe_eee = true;

        auto encrypt_task1_eee = algo_eee.encrypt(test_data);
        auto encrypt_task2_eee = algo_eee.encrypt(test_data);

        auto encrypted1_eee = encrypt_task1_eee.get();
        auto encrypted2_eee = encrypt_task2_eee.get();

        auto final_decrypted_eee = algo_eee.decrypt(encrypted1_eee).get();
        if (!compare_byte_vectors(test_data, final_decrypted_eee)) {
            thread_safe_eee = false;
            std::cout << "Thread safety check failed for EEE - decrypted data doesn't match original" << std::endl;
        }

        runner.assert_true(thread_safe_ede && thread_safe_eee,
                           "Operations should be thread-safe with TripleDES (both EDE and EEE modes)");
        runner.end_test(thread_safe_ede && thread_safe_eee);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void TripleDESTest::test_performance() {
    runner.start_test("Performance Test with TripleDES");

    try {
        auto key = get_default_key();
        auto iv = get_default_iv();

        std::vector<size_t> data_sizes = {64, 512, 4096};

        for (size_t size : data_sizes) {
            std::vector<std::byte> test_data(size);
            for (size_t i = 0; i < size; ++i) {
                test_data[i] = static_cast<std::byte>((i * 7) % 256);
            }

            std::cout << "  Testing data size: " << size << " bytes" << std::endl;

            auto algorithm_ede = create_tripledes_algorithm_ede(key);
            symmetric_context::SymmetricContext algo_ede(key, symmetric_context::EncryptionModes::CFB,
                                                         symmetric_context::PaddingModes::PKCS7, iv, {}, std::move(algorithm_ede));

            auto encrypt_start_ede = std::chrono::high_resolution_clock::now();
            auto encrypted_ede = algo_ede.encrypt(test_data).get();
            auto encrypt_end_ede = std::chrono::high_resolution_clock::now();
            auto encrypt_duration_ede = std::chrono::duration_cast<std::chrono::microseconds>(encrypt_end_ede - encrypt_start_ede);

            auto decrypt_start_ede = std::chrono::high_resolution_clock::now();
            auto decrypted_ede = algo_ede.decrypt(encrypted_ede).get();
            auto decrypt_end_ede = std::chrono::high_resolution_clock::now();
            auto decrypt_duration_ede = std::chrono::duration_cast<std::chrono::microseconds>(decrypt_end_ede - decrypt_start_ede);

            bool success_ede = compare_byte_vectors(test_data, decrypted_ede);

            std::cout << "    EDE - Encrypt: " << encrypt_duration_ede.count()
                      << " ms, Decrypt: " << decrypt_duration_ede.count() << " ms, Success: "
                      << (success_ede ? "Yes" : "No") << std::endl;

            if (!success_ede) {
                runner.end_test(false);
                return;
            }
        }

        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

symmetric_context::EncryptionModes TripleDESTest::get_file_encryption_mode() const {
    return symmetric_context::EncryptionModes::CBC;
}

symmetric_context::PaddingModes TripleDESTest::get_file_padding_mode() const {
    return symmetric_context::PaddingModes::PKCS7;
}

int run_all_tripledes_tests() {
    TestRunner runner;
    TripleDESTest tripledes_test(runner);

    TestFileConfig config;
    tripledes_test.run_all_tests(config);

    runner.print_summary();
    return runner.tests_failed > 0 ? 1 : 0;
}

void run_all_tripledes_tests_with_custom_files(
        const std::filesystem::path& text_file,
        const std::filesystem::path& binary_file,
        const std::filesystem::path& image_file,
        const std::filesystem::path& pdf_file,
        const std::filesystem::path& zip_file,
        const std::filesystem::path& mp4_file
) {
    TestRunner runner;
    TripleDESTest tripledes_test(runner);

    TestFileConfig config;
    config.set_custom_files(text_file, binary_file, image_file, pdf_file, zip_file, mp4_file);

    tripledes_test.run_all_tests(config);
    runner.print_summary();
}