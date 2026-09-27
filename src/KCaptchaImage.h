#ifndef KWAF_CAPTCHA_IMAGE_H
#define KWAF_CAPTCHA_IMAGE_H

#include <stdint.h>
#include <vector>

bool build_captcha_png(int number, uint32_t seed, std::vector<unsigned char>& output);

#endif
