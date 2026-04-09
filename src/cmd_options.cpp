#include "cmd_options.h"
#include <boost/program_options/detail/parsers.hpp>
#include <boost/program_options/value_semantic.hpp>
#include <exception>
#include <iostream>
#include <string>

namespace CryptoGuard {
namespace po = boost::program_options;
ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()("help", "produce help message")("command", po::value<std::string>(),
                                                        "encrypt, decrypt, checksum")(
        "input,i", po::value<std::string>(), "input file")("output,o", po::value<std::string>(), "output file")(
        "password,p", po::value<std::string>(), "password for encrypt/decrypt");
}
ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    po::positional_options_description p;
    p.add("command", 1);

    po::variables_map vm;

    po::store(po::command_line_parser(argc, argv).options(desc_).positional(p).run(), vm);
    po::notify(vm);
    if (vm.size() < 1 || vm.count("help")) {
        std::cerr << desc_ << "\n";
        return;
    }
    if (vm.count("command")) {
        try {
            command_ = commandMapping_.at(vm["command"].as<std::string>());
        } catch (const std::exception &ex) {
            throw;
        }
    }

    if (vm.count("input")) {
        inputFile_ = vm["input"].as<std::string>();
    }
    if (vm.count("output")) {
        outputFile_ = vm["output"].as<std::string>();
    }
    if (vm.count("password")) {
        password_ = vm["password"].as<std::string>();
    }
}

}  // namespace CryptoGuard
