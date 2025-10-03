CXX := clang++
CC := clang
CXXFLAGS := -ggdb -Wall -Wextra -Wpedantic -Wvla -Wshadow $(shell ../build/bin/llvm-config --cxxflags | sed 's/-I/-isystem /g') -isystem ../build/lib/Target/X86 -isystem ../lib/Target/X86 -isystem ../lib/ -fsanitize=address,undefined
CFLAGS := -ggdb -Wall -Wextra -Wpedantic -Wvla -Wshadow -std=c23
LDFLAGS := -fuse-ld=lld $(shell ../build/bin/llvm-config --ldflags --libs all --system-libs)

.PHONY: all clean

all: abisan libabisan_runtime.a

abisan: abisan.cpp
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) $(INCLUDES) -o $@

abisan_runtime.c.o: abisan_runtime.c
	$(CC) -c $(CFLAGS) $^ -o $@

abisan_runtime.S.o: abisan_runtime.S
	$(CC) -c $^ -o $@

libabisan_runtime.a: abisan_runtime.S.o abisan_runtime.c.o
	$(AR) rs $@ $^

clean:
	rm -f abisan abisan_runtime.S.o abisan_runtime.c.o libabisan_runtime.a

fmt:
	clang-format -i *.cpp *.c *.h
