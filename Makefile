CFLAGS := -g -I /usr/local/include/libraw1394 -Wall -Wno-format
LDFLAGS := -lraw1394

all: firescope

firescope: firescope.o
firescope.o: firescope.c firescope.h

firescope32.o: firescope.c firescope.h
	$(CC) $(CFLAGS) -m32 -c -o firescope32.o firescope.c


firescope32: LDFLAGS += -m32
firescope32: firescope32.o

clean:
	rm -f firescope.o firescope32.o firescope firescope32

