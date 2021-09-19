# online-offline-sign

Study project. Implementation of **online/offline signature** scheme.
Currently on prototype phase. 

Uses schemes proposed by Adi Shamir and Yael Tanman in work "Improved Online/Oflline Signature Scheme". 

# Build
## Linux
```
git clone --recurse-submodules https://github.com/levolina/online-offline-sign
cd online-offline-sign
<dependency build> 
make
```
## Windows
```
git clone --recurse-submodules https://github.com/levolina/online-offline-sign
cd online-offline-sign
<dependency build> 
msbuild.exe online-offline-signature.sln
```

# Dependencies
## Botan

**Botan** is a C++ cryptography library released under the permissive [Simplified BSD](https://botan.randombit.net/license.txt) license. Connected to project as a git submodule (official repository: https://github.com/randombit/botan).

Supported signature algorithms: RSA, DSA, ECDSA, ECKCDSA, ECGDSA, GOST 34.10-2001.

On **Linux**:

	./configure.py --prefix=
	make
	make check
	nmake install

> Needs at least gcc 8.0

On **Windows**:

	python configure.py --cc=msvc --os=windows --cpu=generic --prefix=.
	nmake
	nmake check
	nmake install

## Benchmark

**Benchmark** is a library to benchmark code snippets, similar to unit tests. 

On **Linux**:

	# Check out the library.
	$ git clone https://github.com/google/benchmark.git
	# Go to the library root directory
	$ cd benchmark
	# Make a build directory to place the build output.
	$ cmake -E make_directory "build"
	# Generate build system files with cmake, and download any dependencies.
	$ cmake -E chdir "build" cmake -DBENCHMARK_DOWNLOAD_DEPENDENCIES=on -DCMAKE_BUILD_TYPE=Release ../
	# or, starting with CMake 3.13, use a simpler form:
	# cmake -DCMAKE_BUILD_TYPE=Release -S . -B "build"
	# Build the library.
	$ cmake --build "build" --config Release

> Minimum versions to build the library: GCC 4.8, Clang 3.4, Visual Studio 14 2015, Intel 2015 Update 1

On **Windows**:

	TODO
