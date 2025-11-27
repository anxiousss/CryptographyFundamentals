#include "test_deal.hpp"

std::unique_ptr<symmetric_context::SymmetricAlgorithm> DealTest::create_deal_algorithm(const std::vector<std::byte>& key) {
    auto deal_round_key_generation = std::make_shared<deal::DealRoundKeyGeneration>();
    auto des_transformation = std::make_shared<deal::DesTransformation>();
    return std::make_unique<deal::DEAL>(key, deal_round_key_generation, des_transformation);
}

void DealTest::run_all_tests(const TestFileConfig& config) {
    std::string algo_name = "DEAL-" + std::to_string(key_size_);
    std::cout << "Running " << algo_name << " Symmetric Algorithm Tests" << std::endl;
    std::cout << "=====================================================" << std::endl;

    test_basic_encryption_modes(get_key(), get_iv(), create_deal_algorithm, algo_name);
    test_padding_modes(get_key(), get_iv(), create_deal_algorithm);
    test_edge_cases(get_key(), create_deal_algorithm);

    test_thread_safety(algo_name);
    test_performance(algo_name);

    test_file_operations(get_key(), get_iv(), create_deal_algorithm, config, "DEAL");

    test_different_key_sizes();
    test_large_block_operations(algo_name);
}

std::vector<std::byte> DealTest::get_key() const {
    switch (key_size_) {
        case 128:
            return {
                    std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                    std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                    std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                    std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10}
            };
        case 192:
            return {
                    std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                    std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                    std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                    std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10},
                    std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                    std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}
            };
        case 256:
            return {
                    std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                    std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
                    std::byte{0xFE}, std::byte{0xDC}, std::byte{0xBA}, std::byte{0x98},
                    std::byte{0x76}, std::byte{0x54}, std::byte{0x32}, std::byte{0x10},
                    std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                    std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                    std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                    std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
            };
        default:
            throw std::runtime_error("Unsupported key size for DEAL");
    }
}

std::vector<std::byte> DealTest::get_iv() const {
    return {
            std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
            std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22},
            std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66},
            std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0x00}
    };
}

void DealTest::test_thread_safety(const std::string& algorithm_name) {
    runner.start_test("Thread Safety with " + algorithm_name);

    try {
        auto key = get_key();
        auto iv = get_iv();

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
                std::byte{0x99}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}, std::byte{0x00}
        };

        auto algorithm = create_deal_algorithm(key);
        symmetric_context::SymmetricContext algo(key, symmetric_context::EncryptionModes::CBC,
                                                 symmetric_context::PaddingModes::PKCS7, iv, {}, std::move(algorithm));

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

        runner.assert_true(thread_safe, "Operations should be thread-safe with " + algorithm_name);
        runner.end_test(thread_safe);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void DealTest::test_performance(const std::string& algorithm_name) {
    runner.start_test("Performance Test with " + algorithm_name);

    try {
        auto key = get_key();
        auto iv = get_iv();

        std::vector<size_t> data_sizes = {16, 64, 256, 1024, 4096, 16384};

        for (size_t size : data_sizes) {
            std::vector<std::byte> test_data(size);
            for (size_t i = 0; i < size; ++i) {
                test_data[i] = static_cast<std::byte>((i * 7) % 256);
            }

            auto algorithm = create_deal_algorithm(key);
            symmetric_context::SymmetricContext algo(key, symmetric_context::EncryptionModes::CBC,
                                                     symmetric_context::PaddingModes::PKCS7, iv, {}, std::move(algorithm));

            auto encrypt_start = std::chrono::high_resolution_clock::now();
            auto encrypted = algo.encrypt(test_data).get();
            auto encrypt_end = std::chrono::high_resolution_clock::now();
            auto encrypt_duration = std::chrono::duration_cast<std::chrono::microseconds>(encrypt_end - encrypt_start);

            auto decrypt_start = std::chrono::high_resolution_clock::now();
            auto decrypted = algo.decrypt(encrypted).get();
            auto decrypt_end = std::chrono::high_resolution_clock::now();
            auto decrypt_duration = std::chrono::duration_cast<std::chrono::microseconds>(decrypt_end - decrypt_start);

            bool success = compare_byte_vectors(test_data, decrypted);

            double encrypt_throughput = (size / 1024.0 / 1024.0) / (encrypt_duration.count() / 1000000.0);
            double decrypt_throughput = (size / 1024.0 / 1024.0) / (decrypt_duration.count() / 1000000.0);

            std::cout << "  Size " << std::setw(5) << size << " bytes - "
                      << "Encrypt: " << std::setw(6) << encrypt_duration.count() << " ms ("
                      << std::fixed << std::setprecision(2) << encrypt_throughput << " MB/s), "
                      << "Decrypt: " << std::setw(6) << decrypt_duration.count() << " ms ("
                      << std::fixed << std::setprecision(2) << decrypt_throughput << " MB/s), "
                      << "Success: " << (success ? "Yes" : "No") << std::endl;

            if (!success) {
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

void DealTest::test_different_key_sizes() {
    runner.start_test("DEAL Key Size Validation");

    try {
        std::vector<std::byte> key128(16, std::byte{0x01});
        std::vector<std::byte> key192(24, std::byte{0x01});
        std::vector<std::byte> key256(32, std::byte{0x01});

        auto algo128 = create_deal_algorithm(key128);
        auto algo192 = create_deal_algorithm(key192);
        auto algo256 = create_deal_algorithm(key256);

        runner.assert_true(algo128->get_block_size() == 16, "DEAL-128 block size should be 16 bytes");
        runner.assert_true(algo192->get_block_size() == 16, "DEAL-192 block size should be 16 bytes");
        runner.assert_true(algo256->get_block_size() == 16, "DEAL-256 block size should be 16 bytes");

        runner.end_test(true);
    } catch (const std::exception& e) {
        std::cout << "Exception in key size test: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void DealTest::test_large_block_operations(const std::string& algorithm_name) {
    runner.start_test("Large Block Operations with " + algorithm_name);

    try {
        auto key = get_key();
        auto iv = get_iv();

        // Тестируем с разными размерами данных
        std::vector<size_t> test_sizes = {1024, 8192, 32768, 131072}; // 1KB, 8KB, 32KB, 128KB

        for (size_t total_size : test_sizes) {
            std::vector<std::byte> large_data(total_size);
            for (size_t i = 0; i < total_size; ++i) {
                large_data[i] = static_cast<std::byte>((i * 13) % 256);
            }

            auto algorithm = create_deal_algorithm(key);
            symmetric_context::SymmetricContext algo(key, symmetric_context::EncryptionModes::CBC,
                                                     symmetric_context::PaddingModes::PKCS7, iv, {}, std::move(algorithm));

            auto encrypt_start = std::chrono::high_resolution_clock::now();
            auto encrypted = algo.encrypt(large_data).get();
            auto encrypt_end = std::chrono::high_resolution_clock::now();
            auto encrypt_duration = std::chrono::duration_cast<std::chrono::microseconds>(encrypt_end - encrypt_start);

            auto decrypt_start = std::chrono::high_resolution_clock::now();
            auto decrypted = algo.decrypt(encrypted).get();
            auto decrypt_end = std::chrono::high_resolution_clock::now();
            auto decrypt_duration = std::chrono::duration_cast<std::chrono::microseconds>(decrypt_end - decrypt_start);

            bool success = compare_byte_vectors(large_data, decrypted);

            double encrypt_throughput = (total_size / 1024.0 / 1024.0) / (encrypt_duration.count() / 1000000.0);
            double decrypt_throughput = (total_size / 1024.0 / 1024.0) / (decrypt_duration.count() / 1000000.0);

            std::cout << "  " << std::setw(6) << total_size << " bytes: "
                      << "Encrypt: " << std::setw(6) << encrypt_duration.count() << " ms ("
                      << std::fixed << std::setprecision(2) << encrypt_throughput << " MB/s), "
                      << "Decrypt: " << std::setw(6) << decrypt_duration.count() << " ms ("
                      << std::fixed << std::setprecision(2) << decrypt_throughput << " MB/s), "
                      << "Success: " << (success ? "Yes" : "No") << std::endl;

            if (!success) {
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

symmetric_context::EncryptionModes DealTest::get_file_encryption_mode() const {
    return symmetric_context::EncryptionModes::CBC;
}

symmetric_context::PaddingModes DealTest::get_file_padding_mode() const {
    return symmetric_context::PaddingModes::PKCS7;
}

int run_all_deal_tests() {
    TestRunner runner;

    std::cout << "Running ALL DEAL Algorithm Tests" << std::endl;
    std::cout << "================================" << std::endl;

    TestFileConfig config;

    DealTest deal128_test(runner, 128);
    deal128_test.run_all_tests(config);

    DealTest deal192_test(runner, 192);
    deal192_test.run_all_tests(config);

    DealTest deal256_test(runner, 256);
    deal256_test.run_all_tests(config);

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
    TestRunner runner;

    TestFileConfig config;
    config.set_custom_files(text_file, binary_file, image_file, pdf_file, zip_file, mp4_file);

    std::cout << "Running ALL DEAL Algorithm Tests with Custom Files" << std::endl;
    std::cout << "==================================================" << std::endl;

    DealTest deal128_test(runner, 128);
    deal128_test.run_all_tests(config);

    DealTest deal192_test(runner, 192);
    deal192_test.run_all_tests(config);

    DealTest deal256_test(runner, 256);
    deal256_test.run_all_tests(config);

    runner.print_summary();
}