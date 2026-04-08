#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <sstream>
#include <stdexcept>

using namespace CryptoGuard;

class CryptoGuardCtxTest : public ::testing::Test {
protected:
    CryptoGuardCtx crypto;
    const std::string TEST_PASSWORD = "test_password_123";
    const std::string TEST_DATA = "Hello, World! This is a test message for encryption.";

    std::stringstream CreateInputStream(const std::string &data) {
        std::stringstream ss;
        ss << data;
        ss.seekg(0);
        return ss;
    }

    std::string StreamToString(std::iostream &stream) {
        stream.seekg(0);
        std::stringstream buffer;
        buffer << stream.rdbuf();
        return buffer.str();
    }
};

TEST_F(CryptoGuardCtxTest, EncryptSimpleText) {
    std::stringstream inStream = CreateInputStream(TEST_DATA);
    std::stringstream outStream;

    EXPECT_NO_THROW(crypto.EncryptFile(inStream, outStream, TEST_PASSWORD));

    std::string encrypted = StreamToString(outStream);

    EXPECT_FALSE(encrypted.empty());

    EXPECT_NE(encrypted, TEST_DATA);
}

TEST_F(CryptoGuardCtxTest, DecryptReturnsOriginalText) {
    std::stringstream inStream = CreateInputStream(TEST_DATA);
    std::stringstream encryptedStream;
    crypto.EncryptFile(inStream, encryptedStream, TEST_PASSWORD);

    encryptedStream.seekg(0);
    std::stringstream decryptedStream;

    EXPECT_NO_THROW(crypto.DecryptFile(encryptedStream, decryptedStream, TEST_PASSWORD));

    std::string decrypted = StreamToString(decryptedStream);

    EXPECT_EQ(decrypted, TEST_DATA);
}

TEST_F(CryptoGuardCtxTest, DifferentPasswordsProduceDifferentCiphertexts) {
    std::stringstream inStream1 = CreateInputStream(TEST_DATA);
    std::stringstream outStream1;
    crypto.EncryptFile(inStream1, outStream1, "password1");

    std::stringstream inStream2 = CreateInputStream(TEST_DATA);
    std::stringstream outStream2;
    crypto.EncryptFile(inStream2, outStream2, "password2");

    std::string encrypted1 = StreamToString(outStream1);
    std::string encrypted2 = StreamToString(outStream2);

    EXPECT_NE(encrypted1, encrypted2);
}

TEST_F(CryptoGuardCtxTest, WrongPasswordProducesDifferentDecryption) {
    std::stringstream inStream = CreateInputStream(TEST_DATA);
    std::stringstream encryptedStream;
    crypto.EncryptFile(inStream, encryptedStream, "correct_password");

    encryptedStream.seekg(0);
    std::stringstream decryptedStream;
    EXPECT_THROW(crypto.DecryptFile(encryptedStream, decryptedStream, "wrong_password"), std::runtime_error);

    std::string decrypted = StreamToString(decryptedStream);

    EXPECT_NE(decrypted, TEST_DATA);
}

TEST_F(CryptoGuardCtxTest, CalculateChecksumReturnsHexString) {
    std::stringstream inStream = CreateInputStream(TEST_DATA);

    std::string checksum = crypto.CalculateChecksum(inStream);

    // Контрольная сумма не должна быть пустой
    EXPECT_FALSE(checksum.empty());

    for (auto c : checksum) {
        EXPECT_TRUE(std::isxdigit(c)) << "Checksum contains non-hex character: " << c;
    }

    EXPECT_EQ(checksum.length(), 64);
}

TEST_F(CryptoGuardCtxTest, SameDataProducesSameChecksum) {
    std::stringstream inStream1 = CreateInputStream(TEST_DATA);
    std::string checksum1 = crypto.CalculateChecksum(inStream1);

    std::stringstream inStream2 = CreateInputStream(TEST_DATA);
    std::string checksum2 = crypto.CalculateChecksum(inStream2);

    EXPECT_EQ(checksum1, checksum2);
}

TEST_F(CryptoGuardCtxTest, DifferentDataProducesDifferentChecksum) {
    std::stringstream inStream1 = CreateInputStream("Data 1");
    std::string checksum1 = crypto.CalculateChecksum(inStream1);

    std::stringstream inStream2 = CreateInputStream("Data 2");
    std::string checksum2 = crypto.CalculateChecksum(inStream2);

    EXPECT_NE(checksum1, checksum2);
}

TEST_F(CryptoGuardCtxTest, EncryptEmptyStream) {
    std::stringstream inStream;
    std::stringstream outStream;

    EXPECT_NO_THROW(crypto.EncryptFile(inStream, outStream, TEST_PASSWORD));

    std::string encrypted = StreamToString(outStream);
    EXPECT_FALSE(encrypted.empty());
}

TEST_F(CryptoGuardCtxTest, ChecksumOfEmptyStream) {
    std::stringstream inStream;

    std::string checksum = crypto.CalculateChecksum(inStream);

    EXPECT_FALSE(checksum.empty());
    EXPECT_EQ(checksum.length(), 64);
}

TEST_F(CryptoGuardCtxTest, EncryptWithEmptyPassword) {
    std::stringstream inStream = CreateInputStream(TEST_DATA);
    std::stringstream outStream;

    EXPECT_NO_THROW(crypto.EncryptFile(inStream, outStream, ""));

    std::string encrypted = StreamToString(outStream);
    EXPECT_FALSE(encrypted.empty());
}

TEST_F(CryptoGuardCtxTest, EncryptWithVeryLongPassword) {
    std::string longPassword(1000, 'x');

    std::stringstream inStream = CreateInputStream(TEST_DATA);
    std::stringstream outStream;

    EXPECT_NO_THROW(crypto.EncryptFile(inStream, outStream, longPassword));

    std::string encrypted = StreamToString(outStream);
    EXPECT_FALSE(encrypted.empty());
}

TEST_F(CryptoGuardCtxTest, EncryptSpecialCharacters) {
    std::string specialData = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`";

    std::stringstream inStream = CreateInputStream(specialData);
    std::stringstream encryptedStream;
    crypto.EncryptFile(inStream, encryptedStream, TEST_PASSWORD);

    encryptedStream.seekg(0);
    std::stringstream decryptedStream;
    crypto.DecryptFile(encryptedStream, decryptedStream, TEST_PASSWORD);

    std::string decrypted = StreamToString(decryptedStream);
    EXPECT_EQ(decrypted, specialData);
}