#pragma once
#include <string>
#include <stdint.h>


class CRC32
{
private:
    unsigned int nchars = 0;
    uint32_t crc = 0;

public:
    void update(char* buf, size_t buf_size);
    uint32_t digest();
    uint32_t fileCRCcalc(std::string file_path);
};