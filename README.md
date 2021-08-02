# online-offline-sign
Study project. Implementation of online/offline signature scheme
Currently on investigation phase

# Dependency build 

* Botan

On Linux:
in deps/botan run command:
./configure.py --prefix=../../
make
make check


P.S. needs at least gcc 8.0

On Windows (not checked before):
python configure.py --cc=msvc --os=windows
nmake
nmake check
$ nmake install