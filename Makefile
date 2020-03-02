CC=g++
CFLAGS=-std=c++14 -g
OBJ=main.o
Target=pcap_stat

all : ${Target}

${Target}: ${OBJ}
	${CC} ${CFLAGS} -o ${Target} ${OBJ} -lpcap

main.o:
	${CC} ${CFLAGS} -c -o main.o main.cpp -lpcap

clean:
	rm -f ${Target}
	rm -f ${OBJ}

