CC = gcc
CFLAGS = -Wall -Wextra -Iinclude
LDFLAGS = -ldl
SRC = src/pkcs11_wrapper.c src/key_manager.c src/encrypt_service.c
OBJ = $(SRC:.c=.o)
TARGET = pkcs11encryptdecrypt

all: $(TARGET)

$(TARGET): main.o $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

main.o: main.c
	$(CC) $(CFLAGS) -c main.c -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) main.o $(TARGET)

.PHONY: all clean
