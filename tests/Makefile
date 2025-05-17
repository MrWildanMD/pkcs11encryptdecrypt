CC=gcc
CFLAGS=-I../include -Wall -Wextra -g
LDFLAGS=

SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)
TARGET=test_encrypt_service

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(OBJS) $(TARGET)