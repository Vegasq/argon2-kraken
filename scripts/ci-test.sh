if ! [ -d pocl ]; then
    git clone https://github.com/pocl/pocl || exit 1
fi

cd pocl/build || exit 1
make install || exit 1
mkdir -p /etc/OpenCL/vendors || exit 1
cp /usr/local/etc/OpenCL/vendors/pocl.icd /etc/OpenCL/vendors/pocl.icd || exit 1
cd ../.. || exit 1

cd build/$COMPILER-$CUDA || exit 1

./argon2-gpu-test -m opencl -l || exit 1
./argon2-gpu-test -m opencl || exit 1
#CTEST_OUTPUT_ON_FAILURE=1 make test || exit 1
