#include "test_des.hpp"

std::unique_ptr<symmetric_context::SymmetricAlgorithm> DesTest::create_des_algorithm(const std::vector<std::byte>& key) {
    auto des_round_key_generation = std::make_shared<des::DesRoundKeyGeneration>();
    auto feistel_transformation = std::make_shared<des::FeistelTransformation>();
    return std::make_unique<des::DES>(key, des_round_key_generation, feistel_transformation);
}

void DesTest::run_all_tests(const TestFileConfig& config) {
    std::cout << "Running DES Symmetric Algorithm Tests" << std::endl;
    std::cout << "=====================================" << std::endl;

    test_basic_encryption_modes(get_default_key(), get_default_iv(), create_des_algorithm, "DES");
    test_padding_modes(get_default_key(), get_default_iv(), create_des_algorithm);
    test_edge_cases(get_default_key(), create_des_algorithm);

    test_thread_safety();
    test_performance();

    test_file_operations(get_default_key(), get_default_iv(), create_des_algorithm, config, "DES");
}

std::vector<std::byte> DesTest::get_default_key() const {
    return {
            std::byte{0x13}, std::byte{0x34}, std::byte{0x57}, std::byte{0x79},
            std::byte{0x9B}, std::byte{0xBC}, std::byte{0xDF}, std::byte{0xF1}
    };
}

std::vector<std::byte> DesTest::get_default_iv() const {
    return {
            std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD},
            std::byte{0xEE}, std::byte{0xFF}, std::byte{0x11}, std::byte{0x22}
    };
}

void DesTest::test_thread_safety() {
    runner.start_test("Thread Safety with DES");

    try {
        auto key = get_default_key();
        auto iv = get_default_iv();

        std::vector<std::byte> test_data = {
                std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
                std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}
        };

        auto algorithm = create_des_algorithm(key);
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

        runner.assert_true(thread_safe, "Operations should be thread-safe with DES");
        runner.end_test(thread_safe);
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        runner.end_test(false);
    }
}

void DesTest::test_performance() {
    runner.start_test("Performance Test with DES");

    try {
        auto key = get_default_key();
        auto iv = get_default_iv();

        std::vector<size_t> data_sizes = {64, 512, 4096};

        for (size_t size : data_sizes) {
            std::vector<std::byte> test_data(size);
            for (size_t i = 0; i < size; ++i) {
                test_data[i] = static_cast<std::byte>((i * 7) % 256);
            }

            auto algorithm = create_des_algorithm(key);
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

            std::cout << "  Size " << size << " bytes - Encrypt: " << encrypt_duration.count()
                      << " μs, Decrypt: " << decrypt_duration.count() << " μs, Success: "
                      << (success ? "Yes" : "No") << std::endl;

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

symmetric_context::EncryptionModes DesTest::get_file_encryption_mode() const {
    return symmetric_context::EncryptionModes::CBC;
}

symmetric_context::PaddingModes DesTest::get_file_padding_mode() const {
    return symmetric_context::PaddingModes::ISO_10126;
}

int run_all_des_tests() {
    TestRunner runner;
    DesTest des_test(runner);

    TestFileConfig config;
    des_test.run_all_tests(config);

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
    TestRunner runner;
    DesTest des_test(runner);

    TestFileConfig config;
    config.set_custom_files(text_file, binary_file, image_file, pdf_file, zip_file, mp4_file);

    des_test.run_all_tests(config);
    runner.print_summary();
}