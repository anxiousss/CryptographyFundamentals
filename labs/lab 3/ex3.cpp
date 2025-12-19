#include "test_rijndael.hpp"
#include <iostream>

int main() {
    std::cout << "=========================================" << std::endl;
    std::cout << "   RIJNDAEL/AES COMPREHENSIVE TEST SUITE   " << std::endl;
    std::cout << "=========================================" << std::endl;
    std::cout << "Testing multiple configurations:" << std::endl;
    std::cout << "1. AES-128 (128-bit key, 128-bit block)" << std::endl;
    std::cout << "2. AES-192 (192-bit key, 128-bit block)" << std::endl;
    std::cout << "3. AES-256 (256-bit key, 128-bit block)" << std::endl;
    std::cout << "4. Rijndael with 192-bit block" << std::endl;
    std::cout << "5. Rijndael with 256-bit block" << std::endl;
    std::cout << "=========================================\n" << std::endl;

    // Пути к тестовым файлам
    std::filesystem::path test_dir = "test_files";

    // Проверяем наличие директории test_files
    if (!std::filesystem::exists(test_dir)) {
        std::cout << "Note: Directory 'test_files/' not found." << std::endl;
        std::cout << "Creating directory for test files..." << std::endl;
        std::filesystem::create_directories(test_dir);
        std::cout << "Place your test files in 'test_files/' directory:" << std::endl;
        std::cout << "  - test.txt, test.bin, SMILEFACE.jpg, test.pdf, test.zip, test.mp4" << std::endl;
        std::cout << "\nRunning basic tests without files...\n" << std::endl;
        run_basic_rijndael_tests();
        return 0;
    }

    // Пути к конкретным файлам
    std::filesystem::path text_file = test_dir / "test.txt";
    std::filesystem::path binary_file = test_dir / "test.bin";
    std::filesystem::path image_file = test_dir / "SMILEFACE.jpg";
    std::filesystem::path pdf_file = test_dir / "test.pdf";
    std::filesystem::path zip_file = test_dir / "test.zip";
    std::filesystem::path mp4_file = test_dir / "test.mp4";

    // Проверяем наличие файлов
    bool has_files = false;

    if (std::filesystem::exists(text_file)) {
        std::cout << "✓ Text file found: " << text_file << std::endl;
        has_files = true;
    }
    if (std::filesystem::exists(binary_file)) {
        std::cout << "✓ Binary file found: " << binary_file << std::endl;
        has_files = true;
    }
    if (std::filesystem::exists(image_file)) {
        std::cout << "✓ Image file found: " << image_file << std::endl;
        has_files = true;
    }
    if (std::filesystem::exists(pdf_file)) {
        std::cout << "✓ PDF file found: " << pdf_file << std::endl;
        has_files = true;
    }
    if (std::filesystem::exists(zip_file)) {
        std::cout << "✓ ZIP file found: " << zip_file << std::endl;
        has_files = true;
    }
    if (std::filesystem::exists(mp4_file)) {
        std::cout << "✓ MP4 file found: " << mp4_file << std::endl;
        has_files = true;
    }

    if (!has_files) {
        std::cout << "\nNo test files found in 'test_files/' directory." << std::endl;
        std::cout << "Running basic tests only...\n" << std::endl;
        run_basic_rijndael_tests();
    } else {
        std::cout << "\nRunning full test suite with files...\n" << std::endl;
        run_all_rijndael_tests_with_custom_files(
                text_file, binary_file, image_file, pdf_file, zip_file, mp4_file
        );
    }

    std::cout << "\n=========================================" << std::endl;
    std::cout << "          TESTS COMPLETE                 " << std::endl;
    std::cout << "=========================================" << std::endl;

    return 0;
}