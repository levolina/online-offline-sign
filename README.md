# online-offline-sign

Study project. Implementation of **online/offline signature** scheme. This is just a prototype.

Uses schemes proposed by Adi Shamir and Yael Tanman in work "Improved Online/Oflline Signature Scheme". 

# Build
## Linux
```
git clone https://github.com/levolina/online-offline-sign
cd online-offline-sign
mkdir build
cd build
cmake ..
make
```

# Dependencies
## Botan

**Botan** is a C++ cryptography library released under the permissive [Simplified BSD](https://botan.randombit.net/license.txt) license. Connected to project as a git submodule (official repository: https://github.com/randombit/botan).

Supported signature algorithms: RSA, DSA, ECDSA, ECKCDSA, ECGDSA, GOST 34.10-2001.

On **Linux**:
```
./configure.py
make
make check
nmake install
```
> Needs at least gcc 8.0
