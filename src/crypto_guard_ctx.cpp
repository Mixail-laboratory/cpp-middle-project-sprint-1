
#include "crypto_guard_ctx.h"
#include <array>
#include <memory>
#include <string>
#include <vector>

#include <iomanip>
#include <istream>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>

namespace CryptoGuard {

class CryptoGuardCtx::Impl {

    struct AesCipherParams {
        static constexpr size_t KEY_SIZE = 32;         // AES-256 key size
        static constexpr size_t IV_SIZE = 16;          // AES block size (IV length)
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

        int encrypt;                              // 1 for encryption, 0 for decryption
        std::array<unsigned char, KEY_SIZE> key;  // Encryption key
        std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
    };

    AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    }

public:
    std::string CalculateChecksum(std::iostream &inStream) {
        if (!inStream.good()) {
            throw std::runtime_error{"Failed to open stream"};
        }
        std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *ctx) { EVP_MD_CTX_free(ctx); })> mdCtx(EVP_MD_CTX_new());
        if (!EVP_DigestInit_ex(mdCtx.get(), EVP_sha256(), nullptr)) {
            throw std::runtime_error("Failed to initialize SHA256");
        }

        std::string buffer;

        while (std::getline(inStream, buffer)) {
            if (!EVP_DigestUpdate(mdCtx.get(), buffer.data(), inStream.gcount())) {
                throw std::runtime_error("Failed to update digest");
            }
        }

        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len = 0;

        if (!EVP_DigestFinal_ex(mdCtx.get(), hash, &hash_len)) {
            throw std::runtime_error("Failed to finalize digest");
        }

        std::ostringstream oss;
        for (unsigned int i = 0; i < hash_len; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }

        return oss.str();
    }

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        if (!inStream.good() || !outStream.good()) {
            throw std::runtime_error("");
        }
        std::string inputLine;
        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = 1;
        std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })> pCtx(
            EVP_CIPHER_CTX_new());

        if (!EVP_CipherInit_ex(pCtx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                               params.encrypt)) {
            throw std::invalid_argument("");
        }

        std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(16);
        int outLen = 0;
        while (std::getline(inStream, inputLine)) {
            outBuf.resize(inputLine.size() + EVP_MAX_BLOCK_LENGTH);
            std::string output;
            if (!EVP_CipherUpdate(pCtx.get(), outBuf.data(), &outLen,
                                  reinterpret_cast<unsigned char *>(inputLine.data()),
                                  static_cast<int>(inputLine.size()))) {
                throw std::runtime_error("Encryption failed");
            }

            outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);

            outStream.write("\n", 1);
        }
        outBuf.resize(EVP_MAX_BLOCK_LENGTH);
        if (!EVP_CipherFinal_ex(pCtx.get(), outBuf.data(), &outLen)) {
            throw std::runtime_error("Cipher finalization failed");
        }

        if (outLen > 0) {
            outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);
        }
    }

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        if (!inStream.good() || !outStream.good()) {
            throw std::runtime_error("");
        }
        std::string inputLine;
        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = 0;
        std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })> pCtx(
            EVP_CIPHER_CTX_new());

        if (!EVP_CipherInit_ex(pCtx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                               params.encrypt)) {
            throw std::invalid_argument("");
        }

        std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(16);
        int outLen = 0;
        while (std::getline(inStream, inputLine)) {
            outBuf.resize(inputLine.size() + EVP_MAX_BLOCK_LENGTH);
            std::string output;
            if (!EVP_CipherUpdate(pCtx.get(), outBuf.data(), &outLen,
                                  reinterpret_cast<unsigned char *>(inputLine.data()),
                                  static_cast<int>(inputLine.size()))) {
                throw std::runtime_error("Encryption failed");
            }

            outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);

            outStream.write("\n", 1);
        }
        outBuf.resize(EVP_MAX_BLOCK_LENGTH);
        if (!EVP_CipherFinal_ex(pCtx.get(), outBuf.data(), &outLen)) {
            throw std::runtime_error("Cipher finalization failed");
        }

        if (outLen > 0) {
            outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);
        }
    }

    Impl() { OpenSSL_add_all_algorithms(); }

    ~Impl() { EVP_cleanup(); }
};

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
};

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
};

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); };

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

}  // namespace CryptoGuard
