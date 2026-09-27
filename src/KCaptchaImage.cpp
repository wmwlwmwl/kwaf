#include "KCaptchaImage.h"
#include "KCaptchaFont.h"
#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <stddef.h>
#include <zlib.h>

namespace {
	const int image_width = 160;
	const int image_height = 100;
	const int channels = 4;
	const double pi = 3.14159265358979323846;

	struct Color {
		unsigned char red;
		unsigned char green;
		unsigned char blue;
	};

	uint32_t next_random(uint32_t& state)
	{
		if (state == 0) {
			state = 0x6d2b79f5u;
		}
		state ^= state << 13;
		state ^= state >> 17;
		state ^= state << 5;
		return state;
	}

	int random_range(uint32_t& state, int minimum, int maximum)
	{
		return minimum + (int)(next_random(state) % (unsigned)(maximum - minimum + 1));
	}

	void set_pixel(std::vector<unsigned char>& pixels, int x, int y, Color color)
	{
		if (x < 0 || x >= image_width || y < 0 || y >= image_height) {
			return;
		}
		size_t offset = ((size_t)y * image_width + x) * channels;
		pixels[offset] = color.red;
		pixels[offset + 1] = color.green;
		pixels[offset + 2] = color.blue;
		pixels[offset + 3] = 255;
	}

	void draw_disc(std::vector<unsigned char>& pixels, int center_x, int center_y,
		int radius, Color color)
	{
		for (int y = -radius; y <= radius; ++y) {
			for (int x = -radius; x <= radius; ++x) {
				if (x * x + y * y <= radius * radius + 1) {
					set_pixel(pixels, center_x + x, center_y + y, color);
				}
			}
		}
	}

	Color vary_brightness(Color color, uint32_t& random_state)
	{
		int difference = random_range(random_state, -25, 100);
		Color result = {
			(unsigned char)std::max(0, std::min(225, (int)color.red + difference)),
			(unsigned char)std::max(0, std::min(225, (int)color.green + difference)),
			(unsigned char)std::max(0, std::min(225, (int)color.blue + difference))
		};
		return result;
	}

	void draw_digit(std::vector<unsigned char>& pixels, int digit, int x, int y,
		uint32_t& random_state, Color color)
	{
		// The embedded 11x18 font gives curved, proportional digit shapes. A
		// separate row skew and baseline shift make each digit less uniform.
		double skew = random_range(random_state, -45, 45) / 100.0;
		y += random_range(random_state, -4, 4);
		for (int row = 0; row < 18; ++row) {
			int shift = (int)std::lround(skew * (row - 8.5));
			for (int column = 0; column < 11; ++column) {
				if ((captcha_digit_font[digit][row] & (1u << column)) != 0) {
					draw_disc(pixels, x + column * 2 + shift, y + row * 2, 1, color);
				}
			}
		}
	}

	void draw_interference_line(std::vector<unsigned char>& pixels,
		uint32_t& random_state, Color color)
	{
		double amplitude = random_range(random_state, 5, 11);
		double period = random_range(random_state, 90, 160);
		double phase = random_range(random_state, 0, 628) / 100.0;
		int center = random_range(random_state, 44, 56);
		for (int x = 5; x < image_width - 5; ++x) {
			int y = center + (int)std::lround(amplitude *
				std::sin(2.0 * pi * x / period + phase));
			draw_disc(pixels, x, y, 0, color);
		}
	}

	void distort(std::vector<unsigned char>& pixels, uint32_t& random_state)
	{
		std::vector<unsigned char> source;
		source.swap(pixels);
		pixels.assign(source.size(), 0);
		double x_amplitude = random_range(random_state, 2, 5);
		double y_amplitude = random_range(random_state, 2, 5);
		double x_period = random_range(random_state, 90, 150);
		double y_period = random_range(random_state, 95, 170);
		for (int y = 0; y < image_height; ++y) {
			for (int x = 0; x < image_width; ++x) {
				int source_x = x + (int)std::lround(x_amplitude *
					std::sin(2.0 * pi * y / x_period));
				int source_y = y + (int)std::lround(y_amplitude *
					std::cos(2.0 * pi * x / y_period));
				if (source_x < 0 || source_x >= image_width ||
					source_y < 0 || source_y >= image_height) {
					continue;
				}
				size_t to = ((size_t)y * image_width + x) * channels;
				size_t from = ((size_t)source_y * image_width + source_x) * channels;
				for (int channel = 0; channel < channels; ++channel) {
					pixels[to + channel] = source[from + channel];
				}
			}
		}
	}

	void append_u32(std::vector<unsigned char>& output, uint32_t value)
	{
		output.push_back((unsigned char)(value >> 24));
		output.push_back((unsigned char)(value >> 16));
		output.push_back((unsigned char)(value >> 8));
		output.push_back((unsigned char)value);
	}

	uint32_t crc32(const unsigned char* data, size_t size)
	{
		uint32_t crc = 0xffffffffu;
		for (size_t i = 0; i < size; ++i) {
			crc ^= data[i];
			for (int bit = 0; bit < 8; ++bit) {
				crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
			}
		}
		return ~crc;
	}

	void append_chunk(std::vector<unsigned char>& output, const char type[4],
		const std::vector<unsigned char>& data)
	{
		append_u32(output, (uint32_t)data.size());
		size_t crc_start = output.size();
		output.insert(output.end(), type, type + 4);
		output.insert(output.end(), data.begin(), data.end());
		append_u32(output, crc32(output.data() + crc_start, output.size() - crc_start));
	}

}

bool build_captcha_png(int number, uint32_t seed, std::vector<unsigned char>& output)
{
	if (number < 1000 || number > 9999) {
		return false;
	}
	std::vector<unsigned char> pixels((size_t)image_width * image_height * channels, 0);
	uint32_t random_state = seed;
	Color color = {
		(unsigned char)random_range(random_state, 12, 105),
		(unsigned char)random_range(random_state, 12, 105),
		(unsigned char)random_range(random_state, 12, 105)
	};

	int divisor = 1000;
	for (int index = 0; index < 4; ++index) {
		int digit = (number / divisor) % 10;
		divisor /= 10;
		draw_digit(pixels, digit, 27 + index * 28, 31, random_state, color);
	}
	draw_interference_line(pixels, random_state, color);
	distort(pixels, random_state);

	for (int i = 0; i < 28; ++i) {
		int x = random_range(random_state, 3, image_width - 4);
		int y = random_range(random_state, 4, image_height - 5);
		int radius = random_range(random_state, 0, 2);
		draw_disc(pixels, x, y, radius, vary_brightness(color, random_state));
	}

	std::vector<unsigned char> raw;
	raw.reserve((size_t)image_height * (image_width * channels + 1));
	for (int y = 0; y < image_height; ++y) {
		raw.push_back(0);
		size_t row = (size_t)y * image_width * channels;
		raw.insert(raw.end(), pixels.begin() + row,
			pixels.begin() + row + image_width * channels);
	}

	uLongf compressed_size = compressBound((uLong)raw.size());
	std::vector<unsigned char> compressed(compressed_size);
	if (compress2(compressed.data(), &compressed_size, raw.data(),
		(uLong)raw.size(), Z_BEST_SPEED) != Z_OK) {
		return false;
	}
	compressed.resize(compressed_size);

	output.clear();
	static const unsigned char signature[] = { 137, 80, 78, 71, 13, 10, 26, 10 };
	output.insert(output.end(), signature, signature + sizeof(signature));
	std::vector<unsigned char> header;
	append_u32(header, image_width);
	append_u32(header, image_height);
	header.push_back(8);
	header.push_back(6); // RGBA, including a transparent background.
	header.push_back(0);
	header.push_back(0);
	header.push_back(0);
	append_chunk(output, "IHDR", header);
	append_chunk(output, "IDAT", compressed);
	append_chunk(output, "IEND", std::vector<unsigned char>());
	return true;
}
