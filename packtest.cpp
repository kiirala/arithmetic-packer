#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

class Predicter {
public:
  uint32_t Probability() {
    //uint64_t one_num = (uint64_t)(ones + 1) << 32;
    //return one_num / (ones + zeroes + 2);
    return 0x80000000;
  }

  void Update(int bit, uint32_t probability) {
    //if (bit) ones++;
    //else zeroes++;
  }

private:
  //int zeroes, ones;
};

class Encoder {
private:
  uint64_t limitLow;
  uint64_t limitHigh;
  char *encoded;
  int encode_pos;
  int encode_length;

  void WriteBit(int bit) {
    assert(bit == 0 || bit == 1);
    if (!this->encoded) {
      this->encoded = new char[16];
      this->encode_length = 16;
      this->encode_pos = 0;
    }

    if (encode_pos >= encode_length * 8) {
      char *new_encoded = new char[this->encode_length * 2];
      for (int i = 0 ; i < this->encode_length ; ++i) {
	new_encoded[i] = this->encoded[i];
      }
      this->encode_length *= 2;
    }

    this->encoded[this->encode_pos / 8] |= bit << (this->encode_pos % 8);
    this->encode_pos += 1;
  }

public:
  Encoder()
    : encoded(0)
  {
  }

  void EncodeBit(int nextBit, uint64_t probability) {
    uint64_t split = limitHigh - (((limitHigh - limitLow) * probability) >> 32);

    if (nextBit == 0) {
      limitHigh = split;
    }
    else {
      limitLow = split;
    }

    while ((limitLow & 0x80000000ULL) == (limitHigh & 0x80000000ULL)) {
      WriteBit((limitLow & 0x80000000ULL) ? 1 : 0);
      limitLow <<= 1;
      limitHigh <<= 1;
    }
  }

  void Encode(const char *data, int length) {
    this->limitLow = 0;
    this->limitHigh = 0x100000000ULL;
    delete this->encoded;
    this->encoded = 0;

    Predicter pred;
    for (int i = 0 ; i < length ; ++i) {
      char byte = data[i];
      for (int j = 0 ; j < 8 ; ++j) {
	int bit = byte & 1;
	uint64_t prob = pred.Probability();
	this->EncodeBit(bit, prob);
	pred.Update(bit, prob);
	byte >>= 1;
      }
    }
  }

  const char *GetEncoded() {
    while (this->encode_pos % 8) {
      this->WriteBit(this->limitLow & 0x80000000ULL);
      this->limitLow <<= 1;
    }
    return this->encoded;
  }

  int GetEncodedLength() {
    while (this->encode_pos % 8) {
      this->WriteBit(this->limitLow & 0x80000000ULL);
      this->limitLow <<= 1;
    }
    return this->encode_pos / 8;
  }
};

class Decoder {
private:
  const char *encoded;
  size_t encoded_length;
  size_t encoded_pos;
  const char *decoded;
  size_t decoded_length;
  size_t decoded_pos;

  uint32_t range_high;

  int DecodeBit(uint64_t probability) {
    while (range_high < 0x80000000) {
      range_high <<= 1;
      value <<= 1;
      value += ReadBit();
    }

    uin32_t subrange = (range_high * probability) >> 32;
    range_high -= subrange;
    if (value > range_high) {
      value -= range_high;
      range_high = subrange;
      WriteBit(1);
    }
    else {
      WriteBit(0);
    }
  }

public:
  Decoder()
    : encoded(0), decoded(0)
  {
  }

  void Decode(char *data, int len) {
  }
};

int main() {
  const char *text = "Xyzzy";

  Encoder enc;

  printf("Encoding \"%s\" (%lu bytes)\n", text, strlen(text));
  for (size_t i = 0 ; i < strlen(text) ; ++i) {
    printf("%02x ", (unsigned char)text[i]);
    if (i % 8 == 7) printf("\n");
  }
  printf("\n");

  enc.Encode(text, strlen(text));

  int len = enc.GetEncodedLength();
  const char *data = enc.GetEncoded();

  printf("Encoded length %d bytes\n", len);
  for (int i = 0 ; i < len ; ++i) {
    printf("%02x ", (unsigned char)data[i]);
    if (i % 8 == 7) printf("\n");
  }
  printf("\n");

  return 0;
}
