#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <fstream>
#include <iostream>
#include <print>

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);
        CryptoGuard::CryptoGuardCtx cryptoCtx;

        switch (options.GetCommand()) {
        case CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT: {
            std::fstream ifile(options.GetInputFile());
            std::fstream ofile(options.GetOutputFile(), std::ios::out);
            cryptoCtx.EncryptFile(ifile, ofile, options.GetPassword());
            break;
        }
        case CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT: {
            std::fstream ifile(options.GetInputFile());
            std::fstream ofile(options.GetOutputFile(), std::ios::out);
            cryptoCtx.DecryptFile(ifile, ofile, options.GetPassword());
            break;
        }
        case CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM: {
            std::fstream ifile(options.GetInputFile());
            std::println(std::cout, "{}", cryptoCtx.CalculateChecksum(ifile));
            break;
        }
        default:
            break;
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}