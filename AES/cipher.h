#pragma once
#include <cstdint>
class Cipher {
public:
    virtual ~Cipher() = default;
    virtual void encrypt(uint8_t* pt) = 0;
    virtual void decrypt(uint8_t* ct) = 0;
};