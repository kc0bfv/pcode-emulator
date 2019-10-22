CC_OPTS := -Wall

OUT_ARCHES := x86 aarch64

TEST_OUTS := $(patsubst %, test.%.out, ${OUT_ARCHES})

all: ${TEST_OUTS}

%.x86.out: CC=gcc
%.aarch64.out: CC=aarch64-linux-gnu-gcc

test.%.out: test.c
	${CC} ${CC_OPTS} $< -o $@
