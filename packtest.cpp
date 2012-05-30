#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

class Predicter {
public:
  Predicter()
    : previousBits(0)
  {
    for (int i = 0 ; i < 512 ; ++i) this->counts[i] = 0;
  }

  uint32_t Probability() {
    int zeroes = counts[previousBits * 2];
    int ones = counts[previousBits * 2 + 1];

    uint64_t one_num = (uint64_t)(ones + 1) << 32;
    uint64_t prob = one_num / (ones + zeroes + 2);

    assert(prob > 0 && prob < 0xffffffffULL);
    return prob;
  }

  void Update(int bit, uint32_t probability) {
    assert(bit == 0 || bit == 1);
    int amount = 1;
    if (bit) this->counts[this->previousBits * 2 + 1] += amount;
    else this->counts[this->previousBits * 2] += amount;
    this->previousBits = ((this->previousBits << 1) | bit) & 0xff;
  }

  void PrintStatus() {
    printf("Predicter matrix:\n");
    for (int i = 0 ; i < 256 ; ++i) {
      printf("%4d  %4d\n", counts[i * 2], counts[i * 2 + 1]);
    }
  }

private:
  int previousBits;
  int counts[256 * 2];
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
  bool printDebug;

  void WriteBit(int bit) {
    assert(bit == 0 || bit == 1);

    if (this->encode_pos >= this->encode_length * 8) {
      char *new_encoded = new char[this->encode_length * 2];
      for (int i = 0 ; i < this->encode_length ; ++i) {
	new_encoded[i] = this->encoded[i];
      }
      for (int i = this->encode_length ; i < this->encode_length * 2 ; ++i) {
	new_encoded[i] = 0;
      }
      delete [] this->encoded;
      this->encoded = new_encoded;
      this->encode_length *= 2;
    }

    this->encoded[this->encode_pos / 8] |= bit << (this->encode_pos % 8);
    this->encode_pos += 1;
  }

  void EncodeBit(int nextBit, uint64_t probability) {
    //if (this->printDebug) printf("Writing %d\n", nextBit);
    assert(this->limitHigh - this->limitLow >= 0x80000000U);

    uint64_t split = this->limitHigh -
      (((this->limitHigh - this->limitLow) * probability) >> 32);
    assert(split > this->limitLow && split < this->limitHigh);

    //printf("high %08lx, low %08lx\n", limitHigh, limitLow);
    if (this->printDebug) {
      printf("prob=%08lx range=%08lx split=%08lx low=%08lx high=%08lx\n", probability, limitHigh - limitLow, split - limitLow, limitLow, limitHigh);
    }

    if (nextBit == 0) {
      limitHigh = split;
    }
    else {
      limitLow = split;
    }

    while ((limitLow & (1ULL << this->limitHighBit)) ==
	   (limitHigh & (1ULL << this->limitHighBit))) {
      WriteBit((limitLow & (1ULL << this->limitHighBit)) ? 1 : 0);
      this->limitHighBit--;
      limitLow &= (1ULL << (this->limitHighBit + 1ULL)) - 1ULL;
      limitHigh &= (1ULL << (this->limitHighBit + 1ULL)) - 1ULL;
    }

    while (this->limitHigh - this->limitLow < 0x80000000U) {
      this->limitLow <<= 1;
      this->limitHigh <<= 1;
      this->limitHighBit++;
    }
    if (this->limitHighBit >= 60) printf("High bit %02d\n", this->limitHighBit);
  }

  void FinishEncoding() {
    if (!this->finished) {
      while (this->encode_pos % 8) {
	this->WriteBit(0);
      }
      this->finished = true;
    }
  }

public:
  Encoder()
    : encoded(0), printDebug(false)
  {
  }

  ~Encoder() {
    delete [] encoded;
  }

  void Encode(const char *data, int length) {
    this->limitLow = 0;
    this->limitHigh = 0x100000000ULL;
    this->limitHighBit = 31;
    delete [] this->encoded;
    this->encoded = new char[16];
    for (int i = 0 ; i < 16 ; ++i) this->encoded[i] = 0;
    this->encode_length = 16;
    this->encode_pos = 0;
    this->finished = false;

    Predicter pred;
    for (int i = 0 ; i < length ; ++i) {
      char byte = data[i];
      //this->printDebug = (i >= length - 2);
      for (int j = 0 ; j < 8 ; ++j) {
	int bit = byte & 1;
	uint64_t prob = pred.Probability();
	this->EncodeBit(bit, prob);
	pred.Update(bit, prob);
	byte >>= 1;
      }
    }

    int endPosition = this->encode_pos + this->limitHighBit;
    while (this->encode_pos < endPosition) {
      this->EncodeBit(0, 0x80000000U);
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

  bool printDebug;

  void WriteBit(int bit) {
    assert(bit == 0 || bit == 1);

    if (decoded_pos >= decoded_length * 8) {
      char *new_decoded = new char[this->decoded_length * 2];
      for (size_t i = 0 ; i < this->decoded_length ; ++i) {
	new_decoded[i] = this->decoded[i];
      }
      for (size_t i = this->decoded_length ; i < this->decoded_length * 2 ; ++i) {
	new_decoded[i] = 0;
      }
      delete [] this->decoded;
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
    printf("Reading zero\n");
    return 0;
  }

  int DecodeBit(uint64_t probability) {
    assert(this->value < this->range);
    while (this->range < 0x80000000U) {
      this->range <<= 1;
      this->value <<= 1;
      this->value += this->ReadBit();
    }

    uint32_t split = this->range - ((this->range * probability) >> 32);
    assert(split < this->range);
    if (this->printDebug)
      printf("prob=%08lx range=%08x value=%08x split=%08x\n", probability, this->range, this->value, split);

    if (this->value >= split) {
      this->value -= split;
      this->range -= split;
      //if (this->printDebug) printf("Read 1\n");
      return 1;
    }
    else {
      this->range = split;
      //if (this->printDebug) printf("Read 0\n");
      return 0;
    }
  }

public:
  Decoder()
    : encoded(0), decoded(0), printDebug(false)
  {
  }

  ~Decoder() {
    delete [] decoded;
  }

  void Decode(const char *data, size_t len, size_t out_len) {
    this->encoded = data;
    this->encoded_length = len;
    this->encoded_pos = 0;
    delete [] decoded;
    this->decoded = new char[16];
    for (int i = 0 ; i < 16 ; ++i) this->decoded[i] = 0;
    this->decoded_length = 16;
    this->decoded_pos = 0;
    this->range = 1;
    this->value = 0;

    Predicter pred;
    while (this->decoded_pos < out_len * 8) {
      //this->printDebug = (this->decoded_pos >= (out_len - 2) * 8);
      uint32_t prob = pred.Probability();
      int bit = this->DecodeBit(prob);
      this->WriteBit(bit);
      pred.Update(bit, prob);
    }
    //pred.PrintStatus();
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
  //const char *text = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  //const char *text = "The quick brown \xff fox jumps over the lazy dog.\xff";
  //const char *text = "AbCdEfGh";
  const char *text = "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

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
  /*
  for (size_t i = 0 ; i < dec_len ; ++i) {
    printf("%02x ", (unsigned char)dec_data[i]);
    if (i % 16 == 15) printf("\n");
  }
  printf("\n");
  */

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
