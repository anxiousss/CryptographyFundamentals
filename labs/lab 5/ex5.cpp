#include "diffie_hellman.hpp"

int main() {
    auto alice_keys = diffie_hellman::Protocol::generate_alice_keys(2048);
    auto bob_keys = diffie_hellman::Protocol::generate_bob_keys(alice_keys.g, alice_keys.p);

    boost::multiprecision::cpp_int alice_secret =
            diffie_hellman::Protocol::compute_secret_key_alice(bob_keys.B, alice_keys.get_a(), alice_keys.p);

    boost::multiprecision::cpp_int bob_secret =
            diffie_hellman::Protocol::compute_secret_key_bob(alice_keys.A, bob_keys.get_b(), alice_keys.p);


    if (alice_secret == bob_secret) {
        std::cout << "Протокол Диффи-Хеллмана успешно завершен!\n";
        std::cout << "Общий секрет: " << alice_secret << "\n";
        std::cout << "Длина ключа (бит): " << boost::multiprecision::msb(alice_keys.p) + 1 << "\n";
    } else {
        std::cout << "Ошибка: секреты не совпадают!\n";
    }

    return 0;
}