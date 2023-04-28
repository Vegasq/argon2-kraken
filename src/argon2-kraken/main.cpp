#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <sstream>
#include <map>

#include "argon2-gpu-common/argon2params.h"
#include "argon2-opencl/processingunit.h"
#include "argon2-cuda/processingunit.h"
#include "argon2.h"

#include "base64.cpp"
#include "strings_tools.cpp"
#include "waitgroup.cpp"


template <class Device, class GlobalContext,
          class ProgramContext, class ProcessingUnit>
argon2::opencl::Device getOpenCLDeviceToUse()
{
    GlobalContext global;
    auto &devices = global.getAllDevices();

    return devices[0];
}

template <class Device, class GlobalContext,
          class ProgramContext, class ProcessingUnit>
argon2::cuda::Device getCUDADeviceToUse()
{
    GlobalContext global;
    auto &devices = global.getAllDevices();

    return devices[0];
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


int VerifyHashOpenCL(
    const std::vector<std::string> &passwords, 
    const std::string &hash, 
    const argon2::Argon2Params &params, 
    std::string mode, 
    argon2::Type &type, 
    argon2::Version &version
){
    argon2::opencl::Device device = getOpenCLDeviceToUse<argon2::opencl::Device, argon2::opencl::GlobalContext,
                                                        argon2::opencl::ProgramContext, argon2::opencl::ProcessingUnit>();
    argon2::opencl::GlobalContext global;
    argon2::opencl::ProgramContext progCtx(&global, {device}, type, version);
    argon2::opencl::ProcessingUnit processingUnit(&progCtx, &params, &device, passwords.size(), false, false);
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


int VerifyHashCUDA(
    const std::vector<std::string> &passwords, 
    const std::string &hash, 
    const argon2::Argon2Params &params, 
    std::string mode, 
    argon2::Type &type, 
    argon2::Version &version
){
    argon2::cuda::Device device = getCUDADeviceToUse<argon2::cuda::Device, argon2::cuda::GlobalContext,
                                                        argon2::cuda::ProgramContext, argon2::cuda::ProcessingUnit>();
    argon2::cuda::GlobalContext global;
    argon2::cuda::ProgramContext progCtx(&global, {device}, type, version);
    argon2::cuda::ProcessingUnit processingUnit(&progCtx, &params, &device, passwords.size(), false, false);
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


int VerifyHash(
    const std::vector<std::string> &passwords, 
    const std::string &hash, 
    const argon2::Argon2Params &params, 
    std::string mode, 
    argon2::Type &type, 
    argon2::Version &version
){
    if (mode == "opencl") {
        return VerifyHashOpenCL(passwords, hash, params, mode, type, version);
    } else if (mode == "cuda") {
        return VerifyHashCUDA(passwords, hash, params, mode, type, version);
    }


    return -1;
}

extern "C" int Compare(std::string mode, std::string hash, const std::vector<std::string> &passwords)
{
    Argon2ParamsData paramsData = parse_argon2_hash(hash);

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
    return VerifyHash(passwords, hex_hash, params, mode, paramsData.type, paramsData.version);
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
        plain = plain.substr(0, plain.length() - 1);
        data[hash].push_back(plain);
    }

    ll_file.close();
    wl_file.close();

    return data;
}

// Worker function that takes a task and a mutex to protect the output stream
void worker(
    const std::string& task_name, 
    const std::vector<std::string>& task_data, 
    std::string mode,
    std::ofstream& outfile, 
    std::mutex& out_mutex, 
    WaitGroup& wg
) {
    int i = Compare(mode, task_name, task_data);
    if (i >= 0) {
        // Lock the output stream before writing to it
        std::unique_lock<std::mutex> lock(out_mutex);
        outfile << task_name << ":" << task_data[i] << "\n";
    }

    wg.done();
}

int main(int argc, const char *const *argv) {
    if (argc != 5){
        std::cout << "Usage: argon2-kraken [mode: opencl or cuda] [leftlist] [wordlist] [potfile]\n";
        return -1;
    }

    // Build the tasks map
    std::map<std::string, std::vector<std::string>> tasks = buildTasks(argv[2], argv[3]);
    // Open the output file stream
    std::ofstream outfile(argv[4]);

    // Create a mutex to protect the output stream
    std::mutex out_mutex;

    // Create a condition variable to wait for workers to finish
    // std::condition_variable cv;

    // Limit the number of active workers to 4
    const int max_workers = 60;
    WaitGroup wg;

    // Loop over the tasks and create a worker thread for each one
    for (const auto &task : tasks) {
        // Wait for a worker to finish if we have reached the maximum number of active workers
        while (wg.size() > max_workers) {}

        // Create a new worker thread
        std::thread t(worker, task.first, task.second, argv[1], std::ref(outfile), std::ref(out_mutex), std::ref(wg));
        wg.add(1);
        t.detach();
    }

    // std::cout << "doune with dispatching\n";
    wg.wait();

    outfile.close();

    std::cout << "Done\n";
    return 0;
}