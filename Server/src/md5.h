// SHA256.h - header file for SHA-256 cryptographic hash function
// Replacement for MD5 to address CWE-327 vulnerability

// Copyright (c) 2024 OpenBMP Project
// This implementation uses OpenSSL for SHA-256 hashing

// This software is provided "as is," without express or implied warranty 
// of any kind.

#ifndef SHA256_H_
#define SHA256_H_

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <cstring>

using namespace std;

class SHA256 {

public:
// methods for controlled operation:
  SHA256           ();  // simple initializer
  ~SHA256          ();  // destructor

  void  update     (unsigned char *input, unsigned int input_length);
  void  update     (istream& stream);
  void  update     (FILE *file);
  void  update     (ifstream& stream);
  void  finalize   ();

// constructors for special circumstances.  All these constructors finalize
// the SHA256 context.
  SHA256           (unsigned char *string); // digest string, finalize
  SHA256           (istream& stream);       // digest stream, finalize
  SHA256           (FILE *file);            // digest file, close, finalize
  SHA256           (ifstream& stream);      // digest stream, close, finalize

// methods to acquire finalized result
  unsigned char    *raw_digest ();  // digest as a 32-byte binary array
  char *            hex_digest ();  // digest as a 65-byte ascii-hex string
  friend ostream&   operator<< (ostream&, SHA256 context);

  // Compatibility method to get first 16 bytes for existing code using MD5
  void get_hash_16(unsigned char *output);

private:

// private data:
  EVP_MD_CTX *ctx;
  unsigned char digest[SHA256_DIGEST_LENGTH];
  bool finalized;
  char hex_output[SHA256_DIGEST_LENGTH * 2 + 1];

// private methods:
  void init             ();               // called by all constructors
  void cleanup          ();               // cleanup resources
};

// Implementation

inline SHA256::SHA256() {
    init();
}

inline SHA256::~SHA256() {
    cleanup();
}

inline SHA256::SHA256(unsigned char *string) {
    init();
    update(string, strlen((char*)string));
    finalize();
}

inline SHA256::SHA256(istream& stream) {
    init();
    update(stream);
    finalize();
}

inline SHA256::SHA256(FILE *file) {
    init();
    update(file);
    finalize();
}

inline SHA256::SHA256(ifstream& stream) {
    init();
    update(stream);
    finalize();
}

inline void SHA256::init() {
    ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    finalized = false;
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    memset(hex_output, 0, sizeof(hex_output));
}

inline void SHA256::cleanup() {
    if (ctx) {
        EVP_MD_CTX_free(ctx);
        ctx = NULL;
    }
}

inline void SHA256::update(unsigned char *input, unsigned int input_length) {
    if (!finalized) {
        EVP_DigestUpdate(ctx, input, input_length);
    }
}

inline void SHA256::update(istream& stream) {
    unsigned char buffer[1024];
    while (stream.good()) {
        stream.read((char*)buffer, 1024);
        unsigned int len = stream.gcount();
        if (len > 0) {
            update(buffer, len);
        }
    }
}

inline void SHA256::update(FILE *file) {
    unsigned char buffer[1024];
    size_t len;
    while ((len = fread(buffer, 1, 1024, file)) > 0) {
        update(buffer, len);
    }
}

inline void SHA256::update(ifstream& stream) {
    unsigned char buffer[1024];
    while (stream.good()) {
        stream.read((char*)buffer, 1024);
        unsigned int len = stream.gcount();
        if (len > 0) {
            update(buffer, len);
        }
    }
}

inline void SHA256::finalize() {
    if (!finalized) {
        unsigned int len = 0;
        EVP_DigestFinal_ex(ctx, digest, &len);
        finalized = true;
    }
}

inline unsigned char* SHA256::raw_digest() {
    if (!finalized) {
        finalize();
    }
    return digest;
}

inline char* SHA256::hex_digest() {
    if (!finalized) {
        finalize();
    }
    
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex_output + (i * 2), "%02x", digest[i]);
    }
    hex_output[SHA256_DIGEST_LENGTH * 2] = '\0';
    
    return hex_output;
}

inline void SHA256::get_hash_16(unsigned char *output) {
    if (!finalized) {
        finalize();
    }
    // Return first 16 bytes for backward compatibility with MD5-sized hashes
    memcpy(output, digest, 16);
}

inline ostream& operator<<(ostream& stream, SHA256 context) {
    stream << context.hex_digest();
    return stream;
}

#endif // SHA256_H_