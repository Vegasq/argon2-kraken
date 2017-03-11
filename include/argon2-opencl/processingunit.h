#ifndef ARGON2_OPENCL_PROCESSINGUNIT_H
#define ARGON2_OPENCL_PROCESSINGUNIT_H

#include <memory>

#include "programcontext.h"
#include "argon2-gpu-common/argon2params.h"

namespace argon2 {
namespace opencl {

class ProcessingUnit
{
private:
    const ProgramContext *programContext;
    const Argon2Params *params;
    const Device *device;

    std::size_t batchSize;
    std::size_t memorySize;

    bool bySegment;

    cl::CommandQueue cmdQueue;
    cl::Buffer memoryBuffer;
    cl::Buffer debugBuffer;

    void *mappedMemoryBuffer;

    cl::Kernel kernel;
    cl::Event event;

public:
    class PasswordWriter
    {
    private:
        const Argon2Params *params;
        Type type;
        Version version;
        std::uint8_t *dest;

    public:
        PasswordWriter(ProcessingUnit &parent, std::size_t index = 0);

        void moveForward(std::size_t offset);
        void moveBackwards(std::size_t offset);

        void setPassword(const void *pw, std::size_t pwSize) const;
    };

    class HashReader
    {
    private:
        const Argon2Params *params;
        const std::uint8_t *src;
        std::unique_ptr<uint8_t[]> buffer;

    public:
        HashReader(ProcessingUnit &parent, std::size_t index = 0);

        void moveForward(std::size_t offset);
        void moveBackwards(std::size_t offset);

        const void *getHash() const;
    };

    std::size_t getBatchSize() const { return batchSize; }

    ProcessingUnit(
            const ProgramContext *programContext, const Argon2Params *params,
            const Device *device, std::size_t batchSize,
            bool bySegment = true, bool precomputeRefs = false);

    void beginProcessing();
    void endProcessing();
};

} // namespace opencl
} // namespace argon2

#endif // ARGON2_OPENCL_PROCESSINGUNIT_H
