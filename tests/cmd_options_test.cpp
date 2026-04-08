#include "../include/cmd_options.h"
#include <gtest/gtest.h>

using namespace CryptoGuard;

class ProgramOptionsTest : public ::testing::Test {
protected:
    ProgramOptions opts;

    std::string CaptureStderr(std::function<void()> func) {
        std::stringstream buffer;
        std::streambuf *old = std::cerr.rdbuf(buffer.rdbuf());
        func();
        std::cerr.rdbuf(old);
        return buffer.str();
    }
};

TEST_F(ProgramOptionsTest, ParseEncryptCommand) {
    const char *argv[] = {"program", "encrypt", "-i", "input.txt", "-o", "output.txt", "-p", "password123"};
    int argc = 8;

    opts.Parse(argc, const_cast<char **>(argv));

    EXPECT_EQ(opts.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(opts.GetInputFile(), "input.txt");
    EXPECT_EQ(opts.GetOutputFile(), "output.txt");
    EXPECT_EQ(opts.GetPassword(), "password123");
}

TEST_F(ProgramOptionsTest, ParseDecryptCommand) {
    const char *argv[] = {"program", "decrypt", "-i", "encrypted.bin", "-o", "decrypted.txt", "-p", "secret"};
    int argc = 8;

    opts.Parse(argc, const_cast<char **>(argv));

    EXPECT_EQ(opts.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(opts.GetInputFile(), "encrypted.bin");
    EXPECT_EQ(opts.GetOutputFile(), "decrypted.txt");
    EXPECT_EQ(opts.GetPassword(), "secret");
}

TEST_F(ProgramOptionsTest, ParseChecksumCommand) {
    const char *argv[] = {"program", "checksum", "-i", "file.txt"};
    int argc = 4;

    opts.Parse(argc, const_cast<char **>(argv));

    EXPECT_EQ(opts.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(opts.GetInputFile(), "file.txt");
}

TEST_F(ProgramOptionsTest, ParseWithLongOptions) {
    const char *argv[] = {"program", "encrypt", "--input", "in.txt", "--output", "out.txt", "--password", "pass"};
    int argc = 8;

    opts.Parse(argc, const_cast<char **>(argv));

    EXPECT_EQ(opts.GetInputFile(), "in.txt");
    EXPECT_EQ(opts.GetOutputFile(), "out.txt");
    EXPECT_EQ(opts.GetPassword(), "pass");
}

TEST_F(ProgramOptionsTest, ParseWithMixedOptions) {
    const char *argv[] = {"program", "decrypt", "-i", "input.bin", "--output", "output.txt", "-p", "mypass"};
    int argc = 8;

    opts.Parse(argc, const_cast<char **>(argv));

    EXPECT_EQ(opts.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(opts.GetInputFile(), "input.bin");
    EXPECT_EQ(opts.GetOutputFile(), "output.txt");
    EXPECT_EQ(opts.GetPassword(), "mypass");
}

TEST_F(ProgramOptionsTest, HelpOptionPrintsUsage) {
    const char *argv[] = {"program", "--help"};
    int argc = 2;

    std::string output = CaptureStderr([this, argc, argv]() { opts.Parse(argc, const_cast<char **>(argv)); });

    EXPECT_FALSE(output.empty());
    EXPECT_NE(output.find("Allowed options"), std::string::npos);
}

TEST_F(ProgramOptionsTest, UnknownCommandThrowsException) {
    const char *argv[] = {"program", "unknown_command", "-i", "input.txt"};
    int argc = 4;

    EXPECT_THROW(opts.Parse(argc, const_cast<char **>(argv)), std::exception);
}