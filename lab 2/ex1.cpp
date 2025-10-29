#include "number_functions.hpp"

int main() {
   auto [a, b, c] = number_functions::NumberTheoryFunctions::extended_gcd(240, 46);
   std::cout << a << ' ' << b << ' ' << c << std::endl;
}
