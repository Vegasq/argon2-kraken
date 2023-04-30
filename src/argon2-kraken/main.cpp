#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <sstream>
#include <map>
#include <future>
#include <algorithm>

#include "argon2-gpu-common/argon2params.h"
#include "argon2-opencl/processingunit.h"
#include "argon2-cuda/processingunit.h"
#include "argon2.h"

#include "base64.cpp"
#include "strings_tools.cpp"


template <class Device, class GlobalContext, class ProgramContext, class ProcessingUnit>
Device getDeviceToUse()
{
    GlobalContext global;
    auto &devices = global.getAllDevices();
    return devices[0];
}


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


template <typename Device, typename GlobalContext, typename ProgramContext, typename ProcessingUnit>
int compareHashImpl(
    const std::vector<std::string> &passwords, 
    const std::string &hash, 
    const argon2::Argon2Params &params, 
    argon2::Type &type, 
    argon2::Version &version
){
    Device device = getDeviceToUse<Device, GlobalContext, ProgramContext, ProcessingUnit>();
    GlobalContext global;
    ProgramContext progCtx(&global, {device}, type, version);
    ProcessingUnit processingUnit(&progCtx, &params, &device, passwords.size(), false, false);
    std::unique_ptr<uint8_t[]> computedHash(new uint8_t[params.getOutputLength() * passwords.size()]);

    for (std::size_t i = 0; i < passwords.size(); i++) {
        processingUnit.setPassword(i, passwords[i].data(), passwords[i].size());
    }
    
    processingUnit.beginProcessing();
    processingUnit.endProcessing();

    for (std::size_t i = 0; i < passwords.size(); i++) {
        processingUnit.getHash(i, computedHash.get() + i * params.getOutputLength());

        if (std::memcmp(hash.data(), computedHash.get() + i * params.getOutputLength(), params.getOutputLength()) == 0) {
            return i;
        }
    }

    return -1;
}

int Compare(const std::string &mode, const std::string &hash, const std::vector<std::string> &passwords)
{
    Argon2ParamsData paramsData = parseArgon2Hash(hash);

    uint saltSize = paramsData.salt.length();

    // TODO: Why do we get null in it and why .length() counts it in?
    if (paramsData.salt[saltSize-1] == 0) {
        saltSize -= 1;
    }

    const void *salt_pointer = static_cast<const void *>(paramsData.salt.c_str());
    argon2::Argon2Params params(
        paramsData.hash.length() / 2, 
        salt_pointer, saltSize, 
        nullptr, 0, 
        nullptr, 0, 
        paramsData.timeCost, paramsData.memoryCost, paramsData.parallelism);

    std::string hexHash = hexToString(paramsData.hash);

    if (mode == "opencl") {
        return compareHashImpl<argon2::opencl::Device, argon2::opencl::GlobalContext, argon2::opencl::ProgramContext, argon2::opencl::ProcessingUnit>(
            passwords, hexHash, params, paramsData.type, paramsData.version
        );
    } else if (mode == "cuda") {
        return compareHashImpl<argon2::cuda::Device, argon2::cuda::GlobalContext, argon2::cuda::ProgramContext, argon2::cuda::ProcessingUnit>(
            passwords, hexHash, params, paramsData.type, paramsData.version
        );
    }

    return -1;
}

std::map<std::string, std::vector<std::string>> buildTasks(std::string leftlist, std::string wordlist){
    // TODO: memory concerns

    // Open the input files.
    std::ifstream llFile(leftlist);
    if (!llFile.is_open()) {
        throw std::runtime_error("Cannot open llFile");
    }

    std::ifstream wlFile(wordlist);
    if (!wlFile.is_open()) {
        throw std::runtime_error("Cannot open wlFile");
    }

    std::map<std::string, std::vector<std::string>> data;

    // Read the input files and add jobs to the vector.
    std::string hash, plain;
    while (std::getline(llFile, hash) && std::getline(wlFile, plain)) {
        plain = plain.substr(0, plain.length() - 1);
        data[hash].push_back(plain);
    }

    llFile.close();
    wlFile.close();

    return data;
}

// Worker function that takes a task and a mutex to protect the output stream
void worker(
    const std::string& taskName, 
    const std::vector<std::string>& taskData, 
    std::string mode,
    std::ofstream& outfile, 
    std::mutex& outMutex
) {
    int i = Compare(mode, taskName, taskData);
    if (i >= 0) {
        // Lock the output stream before writing to it
        std::unique_lock<std::mutex> lock(outMutex);
        outfile << taskName << ":" << taskData[i] << "\n";
    }
}

void processTasks(
    const std::map<std::string, std::vector<std::string>> &tasks,
    const std::string &mode,
    const std::string &outputFile
) {
    std::ofstream outfile(outputFile);
    std::mutex outMutex;

    const int max_workers = 60;
    std::vector<std::future<void>> futures;

    for (const auto &task : tasks) {
        // Wait for a worker to finish if the maximum number of active workers is reached
        while (futures.size() >= max_workers) {
            auto it = std::remove_if(futures.begin(), futures.end(), [](std::future<void> &f) {
                return f.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
            });

            futures.erase(it, futures.end());

            if (futures.size() < max_workers) {
                break;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        // Create a new worker using std::async
        futures.emplace_back(std::async(std::launch::async, worker, task.first, task.second, mode, std::ref(outfile), std::ref(outMutex)));
    }

    // Wait for all remaining futures to complete
    for (auto &f : futures) {
        f.get();
    }

    outfile.close();
}

int main(int argc, const char *const *argv) {
    if (argc != 5){
        std::cout << "Usage: argon2-kraken [mode: opencl or cuda] [leftlist] [wordlist] [potfile]\n";
        return -1;
    }

    // Build the tasks map
    std::map<std::string, std::vector<std::string>> tasks = buildTasks(argv[2], argv[3]);

    processTasks(tasks, argv[1], argv[4]);

    std::cout << "Done\n";
    return 0;
}