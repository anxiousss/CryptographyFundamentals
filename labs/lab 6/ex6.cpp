#include "test_serpent.hpp"

int main() {
    TestRunner runner;

    // Запускаем базовые тесты Serpent
    SerpentTest serpent_test(runner);
    serpent_test.run_all_tests();

    // Настройка файлов для тестирования (если есть)
    TestFileConfig config;
    // Раскомментируйте и укажите пути к файлам для тестирования операций с файлами
    config.set_custom_files(
            "test_files/test.txt",
            "test_files/test.bin",
            "test_files/SMILEFACE.jpg",
            "test_files/test.pdf",
            "test_files/test.zip",
            "test_files/test.mp4"
    );


    // Если есть файлы для тестирования, запускаем тесты файловых операций
    if (config.has_any_files()) {
        test_serpent_file_operations(runner, config);
    } else {
        std::cout << "\nNo test files provided. Skipping file operations tests." << std::endl;
        std::cout << "To test file operations, set file paths in TestFileConfig." << std::endl;
    }

    // Выводим итоговую статистику
    runner.print_summary();

    return runner.tests_failed == 0 ? 0 : 1;
}