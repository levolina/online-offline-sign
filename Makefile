TARGET=main

INCLUDE_PATH=./deps/include/botan-3
LIBRARY_PATH=./deps/lib

all:
	g++ -o ${TARGET} ${TARGET}.cpp -I${INCLUDE_PATH} -L${LIBRARY_PATH} \
	-lstdc++ -lbotan-3 -Wl,-R${LIBRARY_PATH}
	./${TARGET}

clean:
	rm -f ${TARGET}
	