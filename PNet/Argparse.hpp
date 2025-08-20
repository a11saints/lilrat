#pragma once
#include <argparse/argparse.hpp>

class ArgumentParser {
public:
	ArgumentParser();
	bool Init(std::function<std::vector<std::string>()>fn);
	argparse::ArgumentParser * program;

};