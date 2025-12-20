#include "test_rijndael.hpp"
#include <iostream>

int main() {
    std::cout << "=========================================" << std::endl;
    std::cout << "   RIJNDAEL/AES TEST SUITE WITH POLYNOMIAL SELECTION" << std::endl;
    std::cout << "=========================================" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "1. Run all tests with all polynomials" << std::endl;
    std::cout << "2. Run tests with polynomial selection" << std::endl;
    std::cout << "3. Run basic tests (no files)" << std::endl;
    std::cout << "4. Run file tests with default polynomial" << std::endl;
    std::cout << "=========================================\n" << std::endl;

    std::cout << "Choose option (1-4): ";
    int option;
    std::cin >> option;

    // Пути к тестовым файлам
    std::filesystem::path test_dir = "test_files";

    // Проверяем наличие директории test_files
    if (!std::filesystem::exists(test_dir)) {
        std::cout << "Note: Directory 'test_files/' not found." << std::endl;
        std::cout << "Creating directory for test files..." << std::endl;
        std::filesystem::create_directories(test_dir);
        std::cout << "Place your test files in 'test_files/' directory:" << std::endl;
        std::cout << "  - test.txt, test.bin, SMILEFACE.jpg, test.pdf, test.zip, test.mp4" << std::endl;

        if (option == 1 || option == 2 || option == 4) {
            std::cout << "\nRunning basic tests without files...\n" << std::endl;
            option = 3;
        }
    }

    // Пути к конкретным файлам
    std::filesystem::path text_file = test_dir / "test.txt";
    std::filesystem::path binary_file = test_dir / "test.bin";
    std::filesystem::path image_file = test_dir / "SMILEFACE.jpg";
    std::filesystem::path pdf_file = test_dir / "test.pdf";
    std::filesystem::path zip_file = test_dir / "test.zip";
    std::filesystem::path mp4_file = test_dir / "test.mp4";

    switch (option) {
        case 1:
            std::cout << "\nRunning all tests with all available polynomials...\n" << std::endl;
            run_all_rijndael_tests_with_custom_files(
                    text_file, binary_file, image_file, pdf_file, zip_file, mp4_file
            );
            break;

        case 2:
            std::cout << "\nRunning tests with polynomial selection...\n" << std::endl;
            run_rijndael_tests_with_polynomial_selection(
                    text_file, binary_file, image_file, pdf_file, zip_file, mp4_file
            );
            break;

        case 3:
            std::cout << "\nRunning basic tests without files...\n" << std::endl;
            run_basic_rijndael_tests();
            break;

        case 4:
            std::cout << "\nRunning file tests with default AES polynomial...\n" << std::endl;
            run_all_rijndael_tests_with_custom_files(
                    text_file, binary_file, image_file, pdf_file, zip_file, mp4_file
            );
            break;

        default:
            std::cout << "Invalid option. Please choose 1, 2, 3, or 4." << std::endl;
            return 1;
    }

    std::cout << "\n=========================================" << std::endl;
    std::cout << "          TESTS COMPLETE                 " << std::endl;
    std::cout << "=========================================" << std::endl;

    return 0;
}