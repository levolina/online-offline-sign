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

# Dependency build
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
