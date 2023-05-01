#include <algorithm>
#include <string>
#include <vector>
#include <sstream>

#include "argon2-gpu-common/argon2params.h"
#include "base64.hpp"
#include "strings_tools.hpp"
#include "hash_parser.hpp"


// GetArgon2Type returns the Argon2 type based on the input token
argon2::Type getArgon2Type(const std::string& token)
{
    if (token == "argon2i") return argon2::ARGON2_I;
    if (token == "argon2d") return argon2::ARGON2_D;
    if (token == "argon2id") return argon2::ARGON2_ID;
    throw std::runtime_error("Unknown Argon2 type");
}

// GetArgon2Version returns the Argon2 version based on the input version number
argon2::Version getArgon2Version(int version)
{
    if (version == 13) return argon2::ARGON2_VERSION_10;
    if (version == 19) return argon2::ARGON2_VERSION_13;
    throw std::runtime_error("Unsupported Argon2 version");
}

// ParseArgon2Hash parses the Argon2 hash string and returns an Argon2ParamsData structure
Argon2ParamsData parseArgon2Hash(const std::string& argon2Hash)
{
    std::istringstream hashStream(argon2Hash);
    std::string token;
    std::vector<std::string> tokens;

    // Split the input hash string into tokens
    while (std::getline(hashStream, token, '$'))
    {
        if (!token.empty())
        {
            tokens.push_back(token);
        }
    }

    if (tokens.size() != 5)
    {
        throw std::runtime_error("Failed to parse hash");
    }

    argon2::Type hashType = getArgon2Type(tokens[0]);
    argon2::Version version = getArgon2Version(std::stoi(tokens[1].substr(2)));

    std::istringstream complexityStream(tokens[2]);
    std::string complexityToken;
    uint32_t memCost = 0;
    uint32_t timeCost = 0;
    uint32_t parallelism = 0;

    // Parse the memory cost, time cost, and parallelism
    while (std::getline(complexityStream, complexityToken, ','))
    {
        std::istringstream tokenStream(complexityToken);
        std::string key;
        std::string value;

        std::getline(tokenStream, key, '=');
        std::getline(tokenStream, value, '=');

        if (key == "m") memCost = std::stoi(value);
        else if (key == "t") timeCost = std::stoi(value);
        else if (key == "p") parallelism = std::stoi(value);
    }

    // Decode the salt and hash values
    std::string decodedSalt = base64_decode(tokens[3]);
    std::string decodedHash = base64_decode(tokens[4]);

    // Build the Argon2ParamsData structure
    Argon2ParamsData data = {
        hashType,
        version,
        stringToHex(decodedHash),
        decodedSalt,
        timeCost,
        memCost,
        parallelism,
    };

    return data;
}
