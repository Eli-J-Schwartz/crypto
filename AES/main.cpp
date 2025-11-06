#include <iostream>
#include "Cast256.h"

int main() {
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
    uint8_t pt[] = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";

    Cast256 a(key);
    a.encrypt(pt);
    for (int i = 0; i < 16; i++) std::cout << std::hex << (((int) pt[i]) & 0xff) << std::endl;
    std::cout << std::endl;
    a.decrypt(pt);
    for (int i = 0; i < 16; i++) std::cout << std::hex << (((int) pt[i]) & 0xff) << std::endl;

    return 0;
}
