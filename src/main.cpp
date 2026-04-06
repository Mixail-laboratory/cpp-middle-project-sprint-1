#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <algorithm>
#include <iostream>
#include <print>
#include <stdexcept>
#include <string>

int main(int argc, char *argv[]) {
    try {
        //
        // OpenSSL пример использования:
        //
        // std::string input = "01234567890123456789";
        // std::string output;

        // std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
        // std::vector<unsigned char> inBuf(16);
        // int outLen;

        // // Обрабатываем первые N символов
        // std::copy(input.begin(), std::next(input.begin(), 16), inBuf.begin());
        // EVP_CipherUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(16));
        // for (int i = 0; i < outLen; ++i) {
        //     output.push_back(outBuf[i]);
        // }

        // // Обрабатываем оставшиеся символы
        // std::copy(std::next(input.begin(), 16), input.end(), inBuf.begin());
        // EVP_CipherUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(input.size() - 16));
        // for (int i = 0; i < outLen; ++i) {
        //     output.push_back(outBuf[i]);
        // }

        // // Заканчиваем работу с cipher
        // EVP_CipherFinal_ex(ctx, outBuf.data(), &outLen);
        // for (int i = 0; i < outLen; ++i) {
        //     output.push_back(outBuf[i]);
        // }

        //
        // Конец примера
        //

        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);
        CryptoGuard::CryptoGuardCtx cryptoCtx;

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}