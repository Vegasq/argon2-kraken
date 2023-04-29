#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include "argon2-gpu-common/argon2params.h"
#include "argon2-opencl/processingunit.h"

#include "argon2.h"

#include <iostream>
#include <array>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <iostream>
#include <fstream>
#include <string>

#include <iostream>
#include <vector>
#include <map>
#include <sqlite3.h>

template <class Device, class GlobalContext,
          class ProgramContext, class ProcessingUnit>
argon2::opencl::Device getDeviceToUse()
{
    GlobalContext global;
    auto &devices = global.getAllDevices();

    return devices[0];
}

std::string base64_decode(std::string encoded_str)
{
    std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string decoded_str;

    int padding = 0;
    int bits = 0;
    int count = 0;

    // Pad the input string with '=' characters if needed
    if (encoded_str.length() % 4 != 0)
    {
        encoded_str.append((4 - (encoded_str.length() % 4)), '=');
    }

    for (char c : encoded_str)
    {
        if (c == '=')
        {
            padding++;
        }
        else
        {
            bits = (bits << 6) | base64_chars.find(c);
        }

        count++;

        if (count == 4)
        {
            if (padding == 0)
            {
                decoded_str += static_cast<char>((bits >> 16) & 0xff);
                decoded_str += static_cast<char>((bits >> 8) & 0xff);
                decoded_str += static_cast<char>(bits & 0xff);
            }
            else if (padding == 1)
            {
                decoded_str += static_cast<char>((bits >> 10) & 0xff);
                decoded_str += static_cast<char>((bits >> 2) & 0xff);
            }
            else if (padding == 2)
            {
                decoded_str += static_cast<char>((bits >> 4) & 0xff);
                decoded_str += static_cast<char>((bits << 4) & 0xff);
            }
            else
            {
                // Handle error
            }

            bits = 0;
            count = 0;
            padding = 0;
        }
    }

    return decoded_str;
}

std::string hexToString(const std::string hex_string)
{
    std::string hash;
    for (std::size_t i = 0; i < hex_string.length(); i += 2)
    {
        std::string byte_hex = hex_string.substr(i, 2);
        char byte = (char)strtol(byte_hex.c_str(), nullptr, 16);
        hash += byte;
    }
    return hash;
}

std::string stringToHex(const std::string &input)
{
    std::stringstream ss;
    ss << std::hex << std::uppercase;

    for (size_t i = 0; i < input.length(); ++i)
    {
        int intValue = static_cast<unsigned char>(input[i]);
        ss << ((intValue < 16) ? "0" : "") << intValue;
    }

    return ss.str();
}

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

Argon2ParamsData parse_argon2_hash(const std::string &argon2_hash)
{
    // std::cout << argon2_hash;
    std::istringstream iss(argon2_hash);
    std::string token;

    std::vector<std::string> tokens;

    while (std::getline(iss, token, '$'))
    {
        if (!token.empty())
        {
            // std::cout << token << "\n";
            tokens.push_back(token);
        }
    }

    if (tokens.size() != 5)
    {
        printf("\nBROKEN HASH\n");
    }

    argon2::Type hash_type = argon2::ARGON2_I;
    if (tokens[0] == "argon2i")
    {
        hash_type = argon2::ARGON2_I;
    }
    else if (tokens[0] == "argon2d")
    {
        hash_type = argon2::ARGON2_D;
    }
    else if (tokens[0] == "argon2id")
    {
        hash_type = argon2::ARGON2_ID;
    }
    else
    {
        printf("\nUnknown hash type\n");
    }

    // VERSION
    int version = std::stoi(tokens[1].substr(2));
    argon2::Version aVer;
    if (version == 13)
    {
        aVer = argon2::ARGON2_VERSION_10;
    }
    else if (version == 19)
    {
        aVer = argon2::ARGON2_VERSION_13;
    }

    // printf("VERSION %d\n", version);

    // PARAMS
    std::istringstream iss2(tokens[2]);
    std::string token2;

    uint32_t mem_cost = 0;
    uint32_t time_cost = 0;
    uint32_t parallelism = 0;

    while (std::getline(iss2, token2, ','))
    {
        std::istringstream token_iss(token2);
        std::string key;
        std::string value;

        std::getline(token_iss, key, '=');
        std::getline(token_iss, value, '=');

        if (key == "m")
        {
            mem_cost = std::stoi(value);
        }
        else if (key == "t")
        {
            time_cost = std::stoi(value);
        }
        else if (key == "p")
        {
            parallelism = std::stoi(value);
        }
    }

    std::string decoded_salt = base64_decode(tokens[3]);
    std::string decoded_hash = base64_decode(tokens[4]);
    const void *salt_c = static_cast<const void *>(decoded_salt.c_str());
    std::size_t salt_size_c = decoded_salt.length();

    // std::cout << "ss " << decoded_salt << "\n";
    // std::cout << "dh " << decoded_hash.length() << "\n";

    std::size_t decoded_salt_size_c = decoded_salt.length();
    const void *decoded_salt_c = reinterpret_cast<const void *>(decoded_salt.data());

    Argon2ParamsData data = {
        hash_type,
        aVer,
        stringToHex(decoded_hash),
        decoded_salt,
        time_cost,
        mem_cost,
        parallelism,
    };

    return data;
}

int VerifyHash(const std::vector<std::string> &passwords, const std::string &hash, const argon2::Argon2Params &params, argon2::opencl::Device &device, argon2::Type &type, argon2::Version &version)
{
    argon2::opencl::GlobalContext global;
    argon2::opencl::ProgramContext progCtx(&global, {device}, type, version);
    argon2::opencl::ProcessingUnit processingUnit(&progCtx, &params, &device, passwords.size(), false, false);

    std::unique_ptr<uint8_t[]> computedHash(new uint8_t[params.getOutputLength() * passwords.size()]);

    for (std::size_t i = 0; i < passwords.size(); i++) {
        // std::cout << passwords[i].data() << "\n";
        processingUnit.setPassword(i, passwords[i].data(), passwords[i].size());
    }
    
    // std::cout << "salt size " << params.getSaltLength() << "\n";
    // std::cout << "hash size " << params.getOutputLength() << "\n";


    // std::cout <<"start proc\n";

    processingUnit.beginProcessing();
    processingUnit.endProcessing();

    // std::cout <<"done proc\n";

    for (std::size_t i = 0; i < passwords.size(); i++) {
        processingUnit.getHash(i, computedHash.get() + i * params.getOutputLength());

        std::cout << "Checking guess\n";
        std::cout << passwords[i]  << std::endl;
        std::cout << "expected hash: " << stringToHex(hash.data()) << std::endl;

        std::string out_hash(reinterpret_cast<const char*>(computedHash.get() + i * params.getOutputLength()), params.getOutputLength());
        std::cout << "out hash: " << stringToHex(out_hash) << std::endl;

        if (std::memcmp(hash.data(), computedHash.get() + i * params.getOutputLength(), params.getOutputLength()) == 0) {
            return i;
        }
    }

    // for (std::size_t i = 0; i < passwords.size(); i++) {
    //     if (std::memcmp(hash.data(), computedHash.get() + i * params.getOutputLength(), params.getOutputLength()) == 0) {
    //         return i;
    //     }
    // }

    return -1;
}

extern "C" int Compare(std::string hash, const std::vector<std::string> &passwords)
{
    Argon2ParamsData paramsData = parse_argon2_hash(hash);

    std::cout << hash << "\n";
    std::cout << paramsData.hash << "\n";
    std::cout << paramsData.salt << "\n";

    uint salt_size = paramsData.salt.length();

    if (paramsData.salt[salt_size-1] == 0) {
        salt_size -= 1;
    }

    const void *salt2_c = static_cast<const void *>(paramsData.salt.c_str());
    argon2::Argon2Params params(
        paramsData.hash.length() / 2, 
        salt2_c, salt_size, 
        nullptr, 0, 
        nullptr, 0, 
        paramsData.timeCost, paramsData.memoryCost, paramsData.parallelism);

    std::string hex_hash = hexToString(paramsData.hash);
    // const std::uint8_t *saltBytes2 = static_cast<const std::uint8_t *>(params.getSalt());
    // std::uint32_t saltLength2 = params.getSaltLength();
    argon2::opencl::Device device = getDeviceToUse<argon2::opencl::Device, argon2::opencl::GlobalContext,
                                                   argon2::opencl::ProgramContext, argon2::opencl::ProcessingUnit>();

    return VerifyHash(passwords, hex_hash, params, device, paramsData.type, paramsData.version);
}


std::map<std::string, std::vector<std::string>> buildTasks(std::string leftlist, std::string wordlist){
    // TODO: memory concerns

    // Open the input files.
    std::ifstream ll_file(leftlist);
    if (!ll_file.is_open()) {
        throw std::runtime_error("Cannot open ll_file.txt");
    }

    std::ifstream wl_file(wordlist);
    if (!wl_file.is_open()) {
        throw std::runtime_error("Cannot open wl_file.txt");
    }

    std::map<std::string, std::vector<std::string>> data;

    // Read the input files and add jobs to the vector.
    std::string hash, plain;
    while (std::getline(ll_file, hash) && std::getline(wl_file, plain)) {
        data[hash].push_back(plain);
    }

    ll_file.close();
    wl_file.close();

    return data;
}

int main(int, const char *const *argv)
{
    std::map<std::string, std::vector<std::string>> tasks = buildTasks("/home/vegasq/argon2.ll", "/home/vegasq/argon2.wl");

    for (const auto &task : tasks) {
        int i = Compare(task.first, task.second);
        if (i >= 0)
        {
            std::cout << "Password is correct. " << task.second[i] << std::endl;
        }
        else
        {
            std::cout << "Password is incorrect." << std::endl;
        }
    }
}
