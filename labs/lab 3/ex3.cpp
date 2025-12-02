#include "symmetric_context.hpp"
#include "aes.hpp"

void hello() {
    printf("Hello world\n");
}

void hello(const char* s) {
    printf("Hello %s\n", s);
}

int main() {
    hello();
    return 0;
}