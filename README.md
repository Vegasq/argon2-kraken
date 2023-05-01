# argon2-kraken

Based on the project [argon2-gpu by Ondrej Mosnáček](https://gitlab.com/omos/argon2-gpu).

The [argon2-kraken](https://github.com/vegasq/argon2-kraken) program is a password cracking tool that uses the Argon2 hashing algorithm. The program can use either the OpenCL or CUDA library to run the Argon2 hashing algorithm on the GPU. The program takes in a leftlist file, a wordlist file, and a potfile, and outputs the successfully cracked passwords to the potfile.

This program implements an association attack technique inspired by [hashcat](https://github.com/hashcat/hashcat). Instead of comparing each line from the leftlist with each line from the wordlist, it associates each line from the leftlist with the line in the same position in the wordlist. This approach is intended to improve performance and reduce the amount of time required to crack passwords.

## Usage

```
argon2-kraken [mode: opencl or cuda] [leftlist] [wordlist] [potfile]
```

## Notes

In Argon2, the memory size is defined in kilobytes, and the amount of memory used
is calculated as m times the block size r times the parallelism p.

The block size r is a fixed parameter in Argon2 and is equal to 1024 bytes.
Therefore, with m=65536 and a parallelism factor of p=1, the amount of memory used
would be `m*r*p = 65536*1024*1 = 67,108,864` bytes or 64 MB.
TODO: Detect amount of workers based on available GPU memory.
1080TI I use for testing has 11264 MB of on board memory, example of the hash used for testing:

>> $argon2id$v=19$m=65536,t=1,p=4$qK32Vuin0v8USlgec6lDFw$w5yjWJqZxCfM4EO3S9jBONpfCx0EBlyxd3MfRFhdn6U

```
65536*1024*4 == 268Mb
11264 / 268 == 42 (lol)
```

*BUT!* At least in case of 1080TI we are not getting anywhere close to this memory utilization
(floats around 20%), as GPU chip itself is a bottleneck that is being used up to 99%.


## TODO

1. Bring the rest of CUDA kernel variants
2. Add `precompute` argument

## Building

This project uses the [CMake](https://cmake.org/) build system.

First, if you haven't cloned the repository using `git clone --recursive`, you need to run:

```bash
git submodule update --init
```

Then, to prepare build:

```bash
cmake -DCMAKE_BUILD_TYPE=Release .
```

Finally, just run `make` to build the code. Note that to use the OpenCL backend, you need to have the `data` subdirectory in the working directory (if you have the binaries in a different directory, just create a symlink using `ln -s <path_to_repo>/data data`).
