#ifndef ARGON2_UTILS_H
#define ARGON2_UTILS_H

// #include <algorithm>
// #include <string>
// #include <vector>
// #include <stdexcept>
// #include <sstream>
// #include <cstdint>

#include "argon2-gpu-common/argon2params.h"
// #include "base64.hpp"
// #include "strings_tools.hpp"


// Argon2ParamsData holds the parsed Argon2 hash parameters
struct Argon2ParamsData
{
    argon2::Type type;
    argon2::Version version;
    std::string hash;
    std::string salt;
    std::uint32_t timeCost;
    std::uint32_t memoryCost;
    std::uint32_t parallelism;
};

argon2::Type getArgon2Type(const std::string& token);
argon2::Version getArgon2Version(int version);
Argon2ParamsData parseArgon2Hash(const std::string& argon2Hash);

#endif // ARGON2_UTILS_H