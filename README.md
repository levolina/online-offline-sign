# online-offline-sign
Study project. Implementation of online/offline signature scheme.
Currently on investigation phase

# Dependency build 

* Botan

Download from official repository (https://github.com/randombit/botan) and build. 

Supported signature algorithms: RSA, DSA, ECDSA, ECKCDSA, ECGDSA, GOST 34.10-2001.

On Linux:

```
./configure.py --prefix=
make
make check
```

P.S. needs at least gcc 8.0

On Windows:
```
python configure.py --cc=msvc --os=windows --cpu=generic --prefix=
nmake
nmake check
nmake install
```
