#include <iostream>
#include <fstream>
#include <thread>
#include <map>
#include <future>
#include <algorithm>

#define CL_TARGET_OPENCL_VERSION 300

#include "argon2-gpu-common/argon2params.h"
#include "argon2-opencl/processingunit.h"
#include "argon2-cuda/processingunit.h"
#include "argon2.h"

#include "hash_parser.hpp"
#include "base64.hpp"
#include "strings_tools.hpp"


// In Argon2, the memory size is defined in kilobytes, and the amount of memory used
// is calculated as m times the block size r times the parallelism p.
//
// The block size r is a fixed parameter in Argon2 and is equal to 1024 bytes.
// Therefore, with m=65536 and a parallelism factor of p=1, the amount of memory used
// would be m*r*p = 65536*1024*1 = 67,108,864 bytes or 64 MB.
//
// TODO: Detect amount of workers based on available GPU memory.
// 1080TI I use for testing has 11264 MB of on board memory, example of the hash used for testing:
//
// >> $argon2id$v=19$m=65536,t=1,p=4$qK32Vuin0v8USlgec6lDFw$w5yjWJqZxCfM4EO3S9jBONpfCx0EBlyxd3MfRFhdn6U
//
// 65536*1024*4 == 268Mb
// 11264 / 268 == 42 (lol)
//
// BUT! At least in case of 1080TI we are not getting anywhere close to this memory utilization
// (floats around 20%), as GPU chip itself is a bottleneck that is being used up to 99%.
const int MaxWorkers = 42;


template <class Device, class GlobalContext, class ProgramContext, class ProcessingUnit>
Device getDeviceToUse()
{
    GlobalContext global;
    auto &devices = global.getAllDevices();
    return devices[0];
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
    // I might be mistaken, but enabling precomputation actually decreases the performance.
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

extern "C" int Compare(const std::string &mode, const std::string &hash, const std::vector<std::string> &passwords)
{
    Argon2ParamsData paramsData = parseArgon2Hash(hash);

    std::size_t saltSize = paramsData.salt.length();

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
    } else {
        std::cout << "Unknwon mode " << mode << " user cuda or opencl" << std::endl;
    }

    return -1;
}

std::map<std::string, std::vector<std::string>> buildTasks(std::string leftlist, std::string wordlist){
    // TODO: AS of right now we load entire LL and WL in memory, will not fly for bigger hashlists

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
        outfile << taskName << ":" << taskData[i] << std::endl;
    }
}

void processTasks(
    const std::map<std::string, std::vector<std::string>> &tasks,
    const std::string &mode,
    const std::string &outputFile
) {
    std::ofstream outfile(outputFile);
    std::mutex outMutex;
    std::vector<std::future<void>> futures;

    for (const auto &task : tasks) {
        // Wait for a worker to finish if the maximum number of active workers is reached
        while (futures.size() >= MaxWorkers) {
            auto it = std::remove_if(futures.begin(), futures.end(), [](std::future<void> &f) {
                return f.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
            });

            futures.erase(it, futures.end());

            if (futures.size() < MaxWorkers) {
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
        std::cout << "Usage: argon2-kraken [mode: opencl or cuda] [leftlist] [wordlist] [potfile]" << std::endl;
        return -1;
    }

    // Build the tasks map
    std::map<std::string, std::vector<std::string>> tasks = buildTasks(argv[2], argv[3]);

    processTasks(tasks, argv[1], argv[4]);

    std::cout << "Done" << std::endl;
    return 0;
}
