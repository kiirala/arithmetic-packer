#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

class Predicter {
public:
  Predicter()
    : zeroes(0), ones(0)
  {
  }

  uint32_t Probability() {
    uint64_t one_num = (uint64_t)(ones + 1) << 32;
    uint64_t prob = one_num / (ones + zeroes + 2);
    assert(prob > 0 && prob < 0xffffffffULL);
    return prob;
    //return 0x80000000;
  }

  void Update(int bit, uint32_t probability) {
    if (bit) ones++;
    else zeroes++;
  }

private:
  int zeroes, ones;
};

class Encoder {
private:
  uint64_t limitLow;
  uint64_t limitHigh;
  char *encoded;
  int encode_pos;
  int encode_length;
  bool finished;
  int limitHighBit;

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
      this->encoded = new_encoded;
      this->encode_length *= 2;
    }

    this->encoded[this->encode_pos / 8] |= bit << (this->encode_pos % 8);
    this->encode_pos += 1;
  }

  void EncodeBit(int nextBit, uint64_t probability) {
    uint64_t split = limitHigh - (((limitHigh - limitLow) * probability) >> 32);

    //printf("high %08lx, low %08lx\n", limitHigh, limitLow);
    //printf("prob=%08lx range=%08lx\n", probability, limitHigh - limitLow);

    if (nextBit == 0) {
      limitHigh = split;
    }
    else {
      limitLow = split;
    }

    while ((limitLow & (1ULL << this->limitHighBit)) == (limitHigh & (1ULL << this->limitHighBit))) {
      WriteBit((limitLow & (1ULL << this->limitHighBit)) ? 1 : 0);
      if (this->limitHighBit > 31) {
	this->limitHighBit--;
      }
      else {
	limitLow <<= 1;
	limitHigh <<= 1;
	limitLow &= 0xffffffffULL;
	limitHigh &= 0xffffffffULL;
      }
    }

    while (this->limitHigh - this->limitLow < 0x80000000U) {
      this->limitLow <<= 1;
      this->limitHigh <<= 1;
      this->limitHighBit++;
    }
  }

  void FinishEncoding() {
    if (!this->finished) {
      while ((this->limitLow & (1 << this->limitHighBit)) == (this->limitHigh & (1 << this->limitHighBit))) {
	this->WriteBit((this->limitHigh & (1 << this->limitHighBit)) ? 1 : 0);
	this->limitHighBit--;
      }

      this->WriteBit((this->limitHigh & (1 << this->limitHighBit)) ? 1 : 0);
      this->limitHighBit--;

      while (this->encode_pos % 8) {
	this->WriteBit((this->limitHigh & (1 << this->limitHighBit)) ? 1 : 0);
	this->limitHighBit--;
      }
      this->finished = true;
    }
  }

public:
  Encoder()
    : encoded(0)
  {
  }

  void Encode(const char *data, int length) {
    this->limitLow = 0;
    this->limitHigh = 0x100000000ULL;
    this->limitHighBit = 31;
    delete this->encoded;
    this->encoded = 0;
    this->finished = false;

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
    this->FinishEncoding();
    return this->encoded;
  }

  int GetEncodedLength() {
    this->FinishEncoding();
    return this->encode_pos / 8;
  }
};

class Decoder {
private:
  const char *encoded;
  size_t encoded_length;
  size_t encoded_pos;
  char *decoded;
  size_t decoded_length;
  size_t decoded_pos;

  uint32_t range;
  uint32_t value;

  void WriteBit(int bit) {
    assert(bit == 0 || bit == 1);
    if (!this->decoded) {
      this->decoded = new char[16];
      this->decoded_length = 16;
      this->decoded_pos = 0;
    }

    if (decoded_pos >= decoded_length * 8) {
      char *new_decoded = new char[this->decoded_length * 2];
      for (size_t i = 0 ; i < this->decoded_length ; ++i) {
	new_decoded[i] = this->decoded[i];
      }
      this->decoded = new_decoded;
      this->decoded_length *= 2;
    }

    this->decoded[this->decoded_pos / 8] |= bit << (this->decoded_pos % 8);
    this->decoded_pos += 1;
  }

  int ReadBit() {
    if (this->encoded_pos < this->encoded_length * 8) {
      char byte = this->encoded[this->encoded_pos / 8];
      int bit = 0;
      if ((byte & (1 << (this->encoded_pos % 8)))) {
	bit = 1;
      }
      this->encoded_pos++;
      return bit;
    }
    return 0;
  }

  int DecodeBit(uint64_t probability) {
    while (this->range < 0x80000000U) {
      this->range <<= 1;
      this->value <<= 1;
      this->value += this->ReadBit();
    }

    //printf("prob=%08lx range=%08x\n", probability, this->range);

    uint32_t split = this->range - ((this->range * probability) >> 32);
    if (this->value >= split) {
      this->value -= split;
      this->range -= split;
      return 1;
    }
    else {
      this->range = split;
      return 0;
    }
  }

public:
  Decoder()
    : encoded(0), decoded(0)
  {
  }

  void Decode(const char *data, size_t len, size_t out_len) {
    this->encoded = data;
    this->encoded_length = len;
    this->encoded_pos = 0;
    this->decoded = 0;
    this->decoded_pos = 0;
    this->range = 1;
    this->value = 0;

    Predicter pred;
    while (this->decoded_pos < out_len * 8) {
      uint32_t prob = pred.Probability();
      int bit = this->DecodeBit(prob);
      this->WriteBit(bit);
      pred.Update(bit, prob);
    }
  }

  const char *GetDecoded() {
    while (this->decoded_pos % 8) {
      this->WriteBit(0);
    }
    return this->decoded;
  }

  int GetDecodedLength() {
    while (this->decoded_pos % 8) {
      this->WriteBit(0);
    }
    return this->decoded_pos / 8;
  }
};

int main() {
  const char *text = "The quick brown fox jumps over the lazy dog.";
  //const char *text = "AbCdEfGh";

  printf("Encoding \"%s\" (%lu bytes)\n", text, strlen(text));
  for (size_t i = 0 ; i < strlen(text) ; ++i) {
    printf("%02x ", (unsigned char)text[i]);
    if (i % 16 == 15) printf("\n");
  }
  printf("\n");

  Encoder enc;
  enc.Encode(text, strlen(text));

  int enc_len = enc.GetEncodedLength();
  const char *enc_data = enc.GetEncoded();

  printf("Encoded length %d bytes\n", enc_len);
  for (int i = 0 ; i < enc_len ; ++i) {
    printf("%02x ", (unsigned char)enc_data[i]);
    if (i % 16 == 15) printf("\n");
  }
  printf("\n");

  Decoder dec;
  dec.Decode(enc_data, enc_len, strlen(text));

  size_t dec_len = dec.GetDecodedLength();
  const char *dec_data = dec.GetDecoded();

  printf("Decoded length %ld bytes\n", dec_len);
  for (size_t i = 0 ; i < dec_len ; ++i) {
    printf("%02x ", (unsigned char)dec_data[i]);
    if (i % 16 == 15) printf("\n");
  }
  printf("\n");

  if (strlen(text) != dec_len) {
    printf("Length mismatch");
  }
  else {
    bool match = true;
    for (size_t i = 0 ; i < dec_len ; ++i) {
      if (text[i] != dec_data[i]) {
	printf("First error at byte %ld (%02x != %02x)\n",
	       i, (unsigned char)text[i], (unsigned char)dec_data[i]);
	match = false;
	break;
      }
    }
    if (match) {
      printf("Result matches original\n");
    }
  }

  return 0;
}
