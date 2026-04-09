#pragma once

#include <boost/program_options.hpp>
#include <string>
#include <unordered_map>

namespace CryptoGuard {

class ProgramOptions final {
public:
    ProgramOptions();
    ~ProgramOptions();

    enum class COMMAND_TYPE {
        ENCRYPT,
        DECRYPT,
        CHECKSUM,
    };

    void Parse(int argc, char *argv[]);

    inline COMMAND_TYPE GetCommand() const { return command_; }
    inline std::string GetInputFile() const { return inputFile_; }
    inline std::string GetOutputFile() const { return outputFile_; }
    inline std::string GetPassword() const { return password_; }

private:
    COMMAND_TYPE command_;
    const std::unordered_map<std::string_view, COMMAND_TYPE> commandMapping_ = {
        {"encrypt", ProgramOptions::COMMAND_TYPE::ENCRYPT},
        {"decrypt", ProgramOptions::COMMAND_TYPE::DECRYPT},
        {"checksum", ProgramOptions::COMMAND_TYPE::CHECKSUM},
    };

    std::string inputFile_;
    std::string outputFile_;
    std::string password_;

    boost::program_options::options_description desc_;
};

}  // namespace CryptoGuard
