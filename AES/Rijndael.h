#pragma once
#include <cstdint>

#include "cipher.h"
class Rijndael : Cipher {
public:
    explicit Rijndael(uint8_t* key);
    ~Rijndael() override;
    void encrypt(uint8_t* pt) override;
    void decrypt(uint8_t* ct) override;

private:
    uint8_t* round_keys;
};
