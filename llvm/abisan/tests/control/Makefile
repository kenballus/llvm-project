CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: test

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f test.o test out.s

test.o: test.s
	../../abisan test.s > out.s
	$(CC) -c $(CFLAGS) out.s -o $@

test: main.c test.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
