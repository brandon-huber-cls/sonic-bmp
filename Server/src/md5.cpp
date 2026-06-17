// SHA256.cpp - SHA-256 implementation for OpenBMP
// Replaces MD5 with SHA-256 for secure hash generation
// Uses OpenSSL library for cryptographic operations

// Copyright (c) 2024 OpenBMP Project
// This implementation uses OpenSSL for SHA-256 hashing

#include "md5.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <sstream>

using namespace std;

// MD5 class now uses SHA-256 internally for security
// Interface maintained for backward compatibility
MD5::MD5(){
  init();
}

void MD5::update(uint1 *input, uint4 input_length) {
  if (finalized){
    cerr << "MD5::update: Can't update a finalized digest!" << endl;
    return;
  }

  if (ctx == nullptr) {
    cerr << "MD5::update: Context not initialized!" << endl;
    return;
  }

  EVP_DigestUpdate((EVP_MD_CTX*)ctx, input, input_length);
}

void MD5::update(FILE *file){
  unsigned char buffer[1024];
  int len;

  while ((len=fread(buffer, 1, 1024, file)))
    update(buffer, len);

  fclose(file);
}

void MD5::update(istream& stream){
  unsigned char buffer[1024];
  int len;

  while (stream.good()){
    stream.read((char *)buffer, 1024);
    len=stream.gcount();
    update(buffer, len);
  }
}

void MD5::update(ifstream& stream){
  unsigned char buffer[1024];
  int len;

  while (stream.good()){
    stream.read((char *)buffer, 1024);
    len=stream.gcount();
    update(buffer, len);
  }
}

void MD5::finalize(){
  if (finalized){
    cerr << "MD5::finalize: Already finalized this digest!" << endl;
    return;
  }

  if (ctx == nullptr) {
    cerr << "MD5::finalize: Context not initialized!" << endl;
    return;
  }

  unsigned int digest_len = 0;
  unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
  
  EVP_DigestFinal_ex((EVP_MD_CTX*)ctx, sha256_digest, &digest_len);
  
  // Truncate SHA-256 (32 bytes) to 16 bytes for backward compatibility
  // This maintains the same digest size as MD5 while using secure hashing
  memcpy(digest, sha256_digest, 16);
  
  EVP_MD_CTX_free((EVP_MD_CTX*)ctx);
  ctx = nullptr;
  
  finalized = 1;
}

MD5::MD5(FILE *file){
  init();
  update(file);
  finalize();
}

MD5::MD5(istream& stream){
  init();
  update(stream);
  finalize();
}

MD5::MD5(ifstream& stream){
  init();
  update(stream);
  finalize();
}

MD5::~MD5(){
  if (ctx != nullptr) {
    EVP_MD_CTX_free((EVP_MD_CTX*)ctx);
    ctx = nullptr;
  }
}

unsigned char *MD5::raw_digest(){
  uint1 *s = new uint1[16];

  if (!finalized){
    cerr << "MD5::raw_digest: Can't get digest if you haven't "
         << "finalized the digest!" << endl;
    return ((unsigned char*) "");
  }

  memcpy(s, digest, 16);
  return s;
}

char *MD5::hex_digest(){
  int i;
  char *s = new char[33];

  if (!finalized){
    cerr << "MD5::hex_digest: Can't get digest if you haven't "
         << "finalized the digest!" << endl;
    return const_cast<char *>("");
  }

  for (i=0; i<16; i++)
    sprintf(s+i*2, "%02x", digest[i]);

  s[32]='\0';

  return s;
}

ostream& operator<<(ostream &stream, MD5 context){
  stream << context.hex_digest();
  return stream;
}

// PRIVATE METHODS:

void MD5::init(){
  finalized = 0;
  
  // Initialize OpenSSL EVP context for SHA-256
  ctx = EVP_MD_CTX_new();
  if (ctx == nullptr) {
    cerr << "MD5::init: Failed to create EVP context!" << endl;
    return;
  }
  
  if (EVP_DigestInit_ex((EVP_MD_CTX*)ctx, EVP_sha256(), nullptr) != 1) {
    cerr << "MD5::init: Failed to initialize SHA-256!" << endl;
    EVP_MD_CTX_free((EVP_MD_CTX*)ctx);
    ctx = nullptr;
    return;
  }
  
  memset(digest, 0, sizeof(digest));
}

// Stub methods for removed MD5-specific functions
void MD5::transform(uint1 block[64]){
  // No longer needed - handled by OpenSSL EVP
}

void MD5::encode(uint1 *output, uint4 *input, uint4 len){
  // No longer needed - handled by OpenSSL EVP
}

void MD5::decode(uint4 *output, uint1 *input, uint4 len){
  // No longer needed - handled by OpenSSL EVP
}

unsigned int MD5::rotate_left(uint4 x, uint4 n){
  return (x << n) | (x >> (32-n));
}

unsigned int MD5::F(uint4 x, uint4 y, uint4 z){
  return (x & y) | (~x & z);
}

unsigned int MD5::G(uint4 x, uint4 y, uint4 z){
  return (x & z) | (y & ~z);
}

unsigned int MD5::H(uint4 x, uint4 y, uint4 z){
  return x ^ y ^ z;
}

unsigned int MD5::I(uint4 x, uint4 y, uint4 z){
  return y ^ (x | ~z);
}

void MD5::FF(uint4& a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac){
  a += F(b, c, d) + x + ac;
  a = rotate_left(a, s) + b;
}

void MD5::GG(uint4& a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac){
  a += G(b, c, d) + x + ac;
  a = rotate_left(a, s) + b;
}

void MD5::HH(uint4& a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac){
  a += H(b, c, d) + x + ac;
  a = rotate_left(a, s) + b;
}

void MD5::II(uint4& a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac){
  a += I(b, c, d) + x + ac;
  a = rotate_left(a, s) + b;
}