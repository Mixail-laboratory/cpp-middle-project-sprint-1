#include "cmd_options.h"
#include <boost/program_options/detail/parsers.hpp>
#include <boost/program_options/value_semantic.hpp>
#include <exception>
#include <iostream>
#include <print>
#include <string>
#include <string_view>

namespace CryptoGuard {
namespace po = boost::program_options;
ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()("help", "produce help message")("command", po::value<std::string>(),
                                                        "encrypt, decrypt, checksum")(
        "input", po::value<std::string>(), "input file")("ouput", po::value<std::string>(), "output file")(
        "password", po::value<std::string>(), "password for encrypt/decrypt");
}
ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    po::positional_options_description p;
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);
    po::notify(vm);
    if (vm.size() < 1 || vm.count("help")) {
        std::cerr << desc_ << "\n";
        return;
    }
    if (vm.count("command")) {
        try {
            command_ = commandMapping_.at(vm["command"].as<std::string>());
        } catch (const std::exception &ex) {
            std::string_view msg = ex.what();
            std::print(std::cerr, "Error: {}\n", ex.what());
            throw;
        }
    }

    if (vm.count("input")) {
        inputFile_ = vm["input"].as<std::string>();
    }
    if (vm.count("output")) {
        outputFile_ = vm["ouput"].as<std::string>();
    }
    if (vm.count("password")) {
        password_ = vm["password"].as<std::string>();
    }
}

}  // namespace CryptoGuard
