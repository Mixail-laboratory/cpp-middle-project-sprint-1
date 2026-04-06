
#include "crypto_guard_ctx.h"
#include <array>
#include <memory>

#include <openssl/evp.h>

namespace CryptoGuard {

class CryptoGuardCtx::Impl {

    struct AesCipherParams {
        static const size_t KEY_SIZE = 32;             // AES-256 key size
        static const size_t IV_SIZE = 16;              // AES block size (IV length)
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
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {}

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {}

    std::string CalculateChecksum(std::iostream &inStream) { return "NOT_IMPLEMENTED"; }

    EVP_CIPHER_CTX *ctx_;

public:
    Impl() {
        OpenSSL_add_all_algorithms();
        auto params = CreateChiperParamsFromPassword("12341234");
        params.encrypt = 1;
        ctx_ = EVP_CIPHER_CTX_new();
        EVP_CipherInit_ex(ctx_, params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);
    }

    ~Impl() {
        EVP_CIPHER_CTX_free(ctx_);
        EVP_cleanup();
    }
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

}  // namespace CryptoGuard
