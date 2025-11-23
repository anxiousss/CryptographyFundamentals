// simple_rsa_tests.cpp
#include "test_rsa.hpp"
#include <chrono>

SimpleRSATests::SimpleRSATests()
        : tests_passed(0), tests_failed(0), total_tests(0) {

    // Устанавливаем директории
    test_files_dir = std::filesystem::current_path().parent_path() / "test_files";
    test_dir = create_test_dir();

    std::cout << "Test files directory: " << test_files_dir << std::endl;
    std::cout << "Results directory: " << test_dir << std::endl;

    // Проверяем существование тестовых файлов
    if (!std::filesystem::exists(test_files_dir)) {
        throw std::runtime_error("Test files directory does not exist: " + test_files_dir.string());
    }
}

SimpleRSATests::~SimpleRSATests() {
    // Закомментируйте cleanup() если хотите сохранить результаты
    // cleanup();
}

std::filesystem::path SimpleRSATests::create_test_dir() {
    auto results_dir = std::filesystem::current_path().parent_path() /  "tests/test_rsa/results";
    return results_dir;
}

void SimpleRSATests::cleanup() {
    try {
        if (std::filesystem::exists(test_dir)) {
            std::filesystem::remove_all(test_dir);
            std::cout << "Cleaned up test directory: " << test_dir << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Warning: Could not cleanup test directory: " << e.what() << std::endl;
    }
}

bool SimpleRSATests::compare_files(const std::filesystem::path& file1, const std::filesystem::path& file2) {
    std::ifstream f1(file1, std::ios::binary);
    std::ifstream f2(file2, std::ios::binary);

    if (!f1.is_open() || !f2.is_open()) {
        return false;
    }

    // Проверяем размеры
    f1.seekg(0, std::ios::end);
    f2.seekg(0, std::ios::end);
    if (f1.tellg() != f2.tellg()) {
        return false;
    }

    // Сравниваем содержимое
    f1.seekg(0);
    f2.seekg(0);

    const size_t buffer_size = 4096;
    char buffer1[buffer_size], buffer2[buffer_size];

    while (f1.read(buffer1, buffer_size) || f2.read(buffer2, buffer_size)) {
        size_t count1 = f1.gcount();
        size_t count2 = f2.gcount();

        if (count1 != count2 || memcmp(buffer1, buffer2, count1) != 0) {
            return false;
        }
    }

    return true;
}

// Тесты для существующих файлов
bool SimpleRSATests::test_text_files() {
    total_tests++;
    std::cout << "\n--- Testing Text Files ---" << std::endl;

    try {
        auto input_file = test_files_dir / "test.txt";
        auto encrypted_file = test_dir / "test_encrypted.txt";
        auto decrypted_file = test_dir / "test_decrypted.txt";

        if (!std::filesystem::exists(input_file)) {
            std::cout << "SKIP: Text file not found: " << input_file << std::endl;
            tests_failed++;
            return false;
        }

        std::cout << "Using text file: " << input_file << std::endl;
        std::cout << "File size: " << std::filesystem::file_size(input_file) << " bytes" << std::endl;

        rsa::RSA rsa(rsa::TestTypes::MilerRabinTest, 0.999, 2048);

        // Шифруем
        std::optional<std::filesystem::path> opt_encrypted = encrypted_file;
        auto encrypt_future = rsa.encrypt(input_file, opt_encrypted);
        encrypt_future.get();

        if (!std::filesystem::exists(encrypted_file)) {
            std::cout << "FAIL: Encrypted file not created" << std::endl;
            tests_failed++;
            return false;
        }

        // Дешифруем
        std::optional<std::filesystem::path> opt_decrypted = decrypted_file;
        auto decrypt_future = rsa.decrypt(encrypted_file, opt_decrypted);
        decrypt_future.get();

        if (!std::filesystem::exists(decrypted_file)) {
            std::cout << "FAIL: Decrypted file not created" << std::endl;
            tests_failed++;
            return false;
        }

        // Сравниваем
        if (!compare_files(input_file, decrypted_file)) {
            std::cout << "FAIL: Original and decrypted files differ" << std::endl;
            tests_failed++;
            return false;
        }

        std::cout << "PASS: Text file encryption/decryption successful" << std::endl;
        std::cout << "  Input: " << input_file << std::endl;
        std::cout << "  Encrypted: " << encrypted_file << std::endl;
        std::cout << "  Decrypted: " << decrypted_file << std::endl;
        tests_passed++;
        return true;

    } catch (const std::exception& e) {
        std::cout << "FAIL: Exception in text file test: " << e.what() << std::endl;
        tests_failed++;
        return false;
    }
}

bool SimpleRSATests::test_binary_files() {
    total_tests++;
    std::cout << "\n--- Testing Binary Files ---" << std::endl;

    try {
        auto input_file = test_files_dir / "test.bin";
        auto encrypted_file = test_dir / "test_encrypted.bin";
        auto decrypted_file = test_dir / "test_decrypted.bin";

        if (!std::filesystem::exists(input_file)) {
            std::cout << "SKIP: Binary file not found: " << input_file << std::endl;
            tests_failed++;
            return false;
        }

        std::cout << "Using binary file: " << input_file << std::endl;
        std::cout << "File size: " << std::filesystem::file_size(input_file) << " bytes" << std::endl;

        rsa::RSA rsa(rsa::TestTypes::MilerRabinTest, 0.999, 2048);

        std::optional<std::filesystem::path> opt_encrypted = encrypted_file;
        auto encrypt_future = rsa.encrypt(input_file, opt_encrypted);
        encrypt_future.get();

        std::optional<std::filesystem::path> opt_decrypted = decrypted_file;
        auto decrypt_future = rsa.decrypt(encrypted_file, opt_decrypted);
        decrypt_future.get();

        if (!compare_files(input_file, decrypted_file)) {
            std::cout << "FAIL: Original and decrypted binary files differ" << std::endl;
            tests_failed++;
            return false;
        }

        std::cout << "PASS: Binary file encryption/decryption successful" << std::endl;
        std::cout << "  Input: " << input_file << std::endl;
        std::cout << "  Encrypted: " << encrypted_file << std::endl;
        std::cout << "  Decrypted: " << decrypted_file << std::endl;
        tests_passed++;
        return true;

    } catch (const std::exception& e) {
        std::cout << "FAIL: Exception in binary file test: " << e.what() << std::endl;
        tests_failed++;
        return false;
    }
}

bool SimpleRSATests::test_pdf_files() {
    total_tests++;
    std::cout << "\n--- Testing PDF Files ---" << std::endl;

    try {
        auto input_file = test_files_dir / "test.pdf";
        auto encrypted_file = test_dir / "test_encrypted.pdf";
        auto decrypted_file = test_dir / "test_decrypted.pdf";

        if (!std::filesystem::exists(input_file)) {
            std::cout << "SKIP: PDF file not found: " << input_file << std::endl;
            tests_failed++;
            return false;
        }

        std::cout << "Using PDF file: " << input_file << std::endl;
        std::cout << "File size: " << std::filesystem::file_size(input_file) << " bytes" << std::endl;

        rsa::RSA rsa(rsa::TestTypes::MilerRabinTest, 0.999, 2048);

        std::optional<std::filesystem::path> opt_encrypted = encrypted_file;
        auto encrypt_future = rsa.encrypt(input_file, opt_encrypted);
        encrypt_future.get();

        std::optional<std::filesystem::path> opt_decrypted = decrypted_file;
        auto decrypt_future = rsa.decrypt(encrypted_file, opt_decrypted);
        decrypt_future.get();

        if (!compare_files(input_file, decrypted_file)) {
            std::cout << "FAIL: Original and decrypted PDF files differ" << std::endl;
            tests_failed++;
            return false;
        }

        std::cout << "PASS: PDF file encryption/decryption successful" << std::endl;
        std::cout << "  Input: " << input_file << std::endl;
        std::cout << "  Encrypted: " << encrypted_file << std::endl;
        std::cout << "  Decrypted: " << decrypted_file << std::endl;
        tests_passed++;
        return true;

    } catch (const std::exception& e) {
        std::cout << "FAIL: Exception in PDF file test: " << e.what() << std::endl;
        tests_failed++;
        return false;
    }
}

bool SimpleRSATests::test_zip_files() {
    total_tests++;
    std::cout << "\n--- Testing ZIP Files ---" << std::endl;

    try {
        auto input_file = test_files_dir / "test.zip";
        auto encrypted_file = test_dir / "test_encrypted.zip";
        auto decrypted_file = test_dir / "test_decrypted.zip";

        if (!std::filesystem::exists(input_file)) {
            std::cout << "SKIP: ZIP file not found: " << input_file << std::endl;
            tests_failed++;
            return false;
        }

        std::cout << "Using ZIP file: " << input_file << std::endl;
        std::cout << "File size: " << std::filesystem::file_size(input_file) << " bytes" << std::endl;

        rsa::RSA rsa(rsa::TestTypes::MilerRabinTest, 0.999, 2048);

        std::optional<std::filesystem::path> opt_encrypted = encrypted_file;
        auto encrypt_future = rsa.encrypt(input_file, opt_encrypted);
        encrypt_future.get();

        std::optional<std::filesystem::path> opt_decrypted = decrypted_file;
        auto decrypt_future = rsa.decrypt(encrypted_file, opt_decrypted);
        decrypt_future.get();

        if (!compare_files(input_file, decrypted_file)) {
            std::cout << "FAIL: Original and decrypted ZIP files differ" << std::endl;
            tests_failed++;
            return false;
        }

        std::cout << "PASS: ZIP file encryption/decryption successful" << std::endl;
        std::cout << "  Input: " << input_file << std::endl;
        std::cout << "  Encrypted: " << encrypted_file << std::endl;
        std::cout << "  Decrypted: " << decrypted_file << std::endl;
        tests_passed++;
        return true;

    } catch (const std::exception& e) {
        std::cout << "FAIL: Exception in ZIP file test: " << e.what() << std::endl;
        tests_failed++;
        return false;
    }
}

bool SimpleRSATests::test_mp4_files() {
    total_tests++;
    std::cout << "\n--- Testing MP4 Files ---" << std::endl;

    try {
        // Тестируем оба MP4 файла
        auto input_file1 = test_files_dir / "test.mp4";
        auto input_file2 = test_files_dir / "test2.mp4";

        bool test1_passed = false;
        bool test2_passed = false;

        // Тест первого MP4 файла
        if (std::filesystem::exists(input_file1)) {
            auto encrypted_file1 = test_dir / "test_encrypted.mp4";
            auto decrypted_file1 = test_dir / "test_decrypted.mp4";

            std::cout << "Using MP4 file: " << input_file1 << std::endl;
            std::cout << "File size: " << std::filesystem::file_size(input_file1) << " bytes" << std::endl;

            rsa::RSA rsa(rsa::TestTypes::MilerRabinTest, 0.999, 2048);

            std::optional<std::filesystem::path> opt_encrypted1 = encrypted_file1;
            auto encrypt_future1 = rsa.encrypt(input_file1, opt_encrypted1);
            encrypt_future1.get();

            std::optional<std::filesystem::path> opt_decrypted1 = decrypted_file1;
            auto decrypt_future1 = rsa.decrypt(encrypted_file1, opt_decrypted1);
            decrypt_future1.get();

            test1_passed = compare_files(input_file1, decrypted_file1);
            if (test1_passed) {
                std::cout << "PASS: First MP4 file encryption/decryption successful" << std::endl;
            } else {
                std::cout << "FAIL: First MP4 file test failed" << std::endl;
            }
        } else {
            std::cout << "SKIP: First MP4 file not found: " << input_file1 << std::endl;
        }

        // Тест второго MP4 файла
        if (std::filesystem::exists(input_file2)) {
            auto encrypted_file2 = test_dir / "test2_encrypted.mp4";
            auto decrypted_file2 = test_dir / "test2_decrypted.mp4";

            std::cout << "Using MP4 file: " << input_file2 << std::endl;
            std::cout << "File size: " << std::filesystem::file_size(input_file2) << " bytes" << std::endl;

            rsa::RSA rsa(rsa::TestTypes::MilerRabinTest, 0.999, 2048);

            std::optional<std::filesystem::path> opt_encrypted2 = encrypted_file2;
            auto encrypt_future2 = rsa.encrypt(input_file2, opt_encrypted2);
            encrypt_future2.get();

            std::optional<std::filesystem::path> opt_decrypted2 = decrypted_file2;
            auto decrypt_future2 = rsa.decrypt(encrypted_file2, opt_decrypted2);
            decrypt_future2.get();

            test2_passed = compare_files(input_file2, decrypted_file2);
            if (test2_passed) {
                std::cout << "PASS: Second MP4 file encryption/decryption successful" << std::endl;
            } else {
                std::cout << "FAIL: Second MP4 file test failed" << std::endl;
            }
        } else {
            std::cout << "SKIP: Second MP4 file not found: " << input_file2 << std::endl;
        }

        bool overall_passed = test1_passed || test2_passed; // Хотя бы один должен пройти

        if (overall_passed) {
            tests_passed++;
            return true;
        } else {
            tests_failed++;
            return false;
        }

    } catch (const std::exception& e) {
        std::cout << "FAIL: Exception in MP4 file test: " << e.what() << std::endl;
        tests_failed++;
        return false;
    }
}

bool SimpleRSATests::test_jpg_files() {
    total_tests++;
    std::cout << "\n--- Testing JPG Files ---" << std::endl;

    try {
        auto input_file = test_files_dir / "SMILEFACE.jpg";
        auto encrypted_file = test_dir / "SMILEFACE_encrypted.jpg";
        auto decrypted_file = test_dir / "SMILEFACE_decrypted.jpg";

        if (!std::filesystem::exists(input_file)) {
            std::cout << "SKIP: JPG file not found: " << input_file << std::endl;
            tests_failed++;
            return false;
        }

        std::cout << "Using JPG file: " << input_file << std::endl;
        std::cout << "File size: " << std::filesystem::file_size(input_file) << " bytes" << std::endl;

        rsa::RSA rsa(rsa::TestTypes::MilerRabinTest, 0.999, 2048);

        std::optional<std::filesystem::path> opt_encrypted = encrypted_file;
        auto encrypt_future = rsa.encrypt(input_file, opt_encrypted);
        encrypt_future.get();

        std::optional<std::filesystem::path> opt_decrypted = decrypted_file;
        auto decrypt_future = rsa.decrypt(encrypted_file, opt_decrypted);
        decrypt_future.get();

        if (!compare_files(input_file, decrypted_file)) {
            std::cout << "FAIL: Original and decrypted JPG files differ" << std::endl;
            tests_failed++;
            return false;
        }

        std::cout << "PASS: JPG file encryption/decryption successful" << std::endl;
        std::cout << "  Input: " << input_file << std::endl;
        std::cout << "  Encrypted: " << encrypted_file << std::endl;
        std::cout << "  Decrypted: " << decrypted_file << std::endl;
        tests_passed++;
        return true;

    } catch (const std::exception& e) {
        std::cout << "FAIL: Exception in JPG file test: " << e.what() << std::endl;
        tests_failed++;
        return false;
    }
}

bool SimpleRSATests::test_different_key_sizes() {
    total_tests++;
    std::cout << "\n--- Testing Different Key Sizes ---" << std::endl;

    try {
        auto input_file = test_files_dir / "test.bin";

        if (!std::filesystem::exists(input_file)) {
            std::cout << "SKIP: Test file not found: " << input_file << std::endl;
            tests_failed++;
            return false;
        }

        // Тест с 1024-битным ключом
        rsa::RSA rsa_1024(rsa::TestTypes::MilerRabinTest, 0.999, 1024);
        auto encrypted_1024 = test_dir / "test_encrypted_1024.bin";
        auto decrypted_1024 = test_dir / "test_decrypted_1024.bin";

        std::optional<std::filesystem::path> opt_encrypted_1024 = encrypted_1024;
        auto encrypt_future_1024 = rsa_1024.encrypt(input_file, opt_encrypted_1024);
        encrypt_future_1024.get();

        std::optional<std::filesystem::path> opt_decrypted_1024 = decrypted_1024;
        auto decrypt_future_1024 = rsa_1024.decrypt(encrypted_1024, opt_decrypted_1024);
        decrypt_future_1024.get();

        if (!compare_files(input_file, decrypted_1024)) {
            std::cout << "FAIL: 1024-bit key test failed" << std::endl;
            tests_failed++;
            return false;
        }

        // Тест с 2048-битным ключом
        rsa::RSA rsa_2048(rsa::TestTypes::MilerRabinTest, 0.999, 2048);
        auto encrypted_2048 = test_dir / "test_encrypted_2048.bin";
        auto decrypted_2048 = test_dir / "test_decrypted_2048.bin";

        std::optional<std::filesystem::path> opt_encrypted_2048 = encrypted_2048;
        auto encrypt_future_2048 = rsa_2048.encrypt(input_file, opt_encrypted_2048);
        encrypt_future_2048.get();

        std::optional<std::filesystem::path> opt_decrypted_2048 = decrypted_2048;
        auto decrypt_future_2048 = rsa_2048.decrypt(encrypted_2048, opt_decrypted_2048);
        decrypt_future_2048.get();

        if (!compare_files(input_file, decrypted_2048)) {
            std::cout << "FAIL: 2048-bit key test failed" << std::endl;
            tests_failed++;
            return false;
        }

        // Проверяем, что зашифрованные файлы разные
        if (compare_files(encrypted_1024, encrypted_2048)) {
            std::cout << "FAIL: Different keys produced identical encrypted files" << std::endl;
            tests_failed++;
            return false;
        }

        std::cout << "PASS: Different key sizes test successful" << std::endl;
        std::cout << "  1024-bit: " << encrypted_1024 << " -> " << decrypted_1024 << std::endl;
        std::cout << "  2048-bit: " << encrypted_2048 << " -> " << decrypted_2048 << std::endl;
        tests_passed++;
        return true;

    } catch (const std::exception& e) {
        std::cout << "FAIL: Exception in key sizes test: " << e.what() << std::endl;
        tests_failed++;
        return false;
    }
}

bool SimpleRSATests::test_auto_generated_filenames() {
    total_tests++;
    std::cout << "\n--- Testing Auto-generated Filenames ---" << std::endl;

    try {
        auto input_file = test_files_dir / "test.txt";

        if (!std::filesystem::exists(input_file)) {
            std::cout << "SKIP: Test file not found: " << input_file << std::endl;
            tests_failed++;
            return false;
        }

        rsa::RSA rsa(rsa::TestTypes::MilerRabinTest, 0.999, 2048);

        // Шифруем без указания выходного файла
        std::optional<std::filesystem::path> no_output = std::nullopt;
        auto encrypt_future = rsa.encrypt(input_file, no_output);
        encrypt_future.get();

        // Проверяем автоматическое имя в директории исходного файла
        auto expected_encrypted = test_files_dir / "test_encrypted.txt";
        if (!std::filesystem::exists(expected_encrypted)) {
            std::cout << "FAIL: Auto-generated encrypted file not found" << std::endl;
            tests_failed++;
            return false;
        }

        // Дешифруем без указания выходного файла
        auto decrypt_future = rsa.decrypt(expected_encrypted, no_output);
        decrypt_future.get();

        // Проверяем автоматическое имя
        auto expected_decrypted = test_files_dir / "test_decrypted.txt";
        if (!std::filesystem::exists(expected_decrypted)) {
            std::cout << "FAIL: Auto-generated decrypted file not found" << std::endl;
            tests_failed++;
            return false;
        }

        if (!compare_files(input_file, expected_decrypted)) {
            std::cout << "FAIL: Auto-named files test failed - content mismatch" << std::endl;
            tests_failed++;
            return false;
        }

        std::cout << "PASS: Auto-generated filenames test successful" << std::endl;
        std::cout << "  Input: " << input_file << std::endl;
        std::cout << "  Auto-encrypted: " << expected_encrypted << std::endl;
        std::cout << "  Auto-decrypted: " << expected_decrypted << std::endl;
        tests_passed++;
        return true;

    } catch (const std::exception& e) {
        std::cout << "FAIL: Exception in auto-generated filenames test: " << e.what() << std::endl;
        tests_failed++;
        return false;
    }
}

bool SimpleRSATests::test_error_handling() {
    total_tests++;
    std::cout << "\n--- Testing Error Handling ---" << std::endl;

    bool all_passed = true;

    // Тест несуществующего файла
    try {
        rsa::RSA rsa(rsa::TestTypes::MilerRabinTest, 0.999, 2048);
        auto non_existent = test_dir / "non_existent_file_12345.bin";
        std::optional<std::filesystem::path> output = test_dir / "output.bin";

        auto future = rsa.encrypt(non_existent, output);
        future.get();

        std::cout << "FAIL: Should have thrown exception for non-existent file" << std::endl;
        all_passed = false;

    } catch (const std::exception&) {
        std::cout << "PASS: Correctly handled non-existent file" << std::endl;
    }

    if (all_passed) {
        tests_passed++;
    } else {
        tests_failed++;
    }

    return all_passed;
}

bool SimpleRSATests::run_all_tests() {
    std::cout << "=== Starting RSA File Encryption Tests ===" << std::endl;
    std::cout << "Using existing files from: " << test_files_dir << std::endl;

    bool all_passed = true;

    // Запускаем все тесты
    all_passed &= test_text_files();
    all_passed &= test_binary_files();
    all_passed &= test_pdf_files();
    all_passed &= test_zip_files();
    all_passed &= test_mp4_files();
    all_passed &= test_jpg_files();
    all_passed &= test_different_key_sizes();
    all_passed &= test_error_handling();

    print_stats();

    if (all_passed) {
        std::cout << "=== ALL TESTS PASSED ===" << std::endl;
    } else {
        std::cout << "=== SOME TESTS FAILED ===" << std::endl;
    }

    return all_passed;
}

void SimpleRSATests::print_stats() const {
    std::cout << "\n=== Test Statistics ===" << std::endl;
    std::cout << "Total tests: " << total_tests << std::endl;
    std::cout << "Passed: " << tests_passed << std::endl;
    std::cout << "Failed: " << tests_failed << std::endl;
    std::cout << "Success rate: " << (total_tests > 0 ? (tests_passed * 100 / total_tests) : 0) << "%" << std::endl;
    std::cout << "Test results location: " << test_dir << std::endl;
}