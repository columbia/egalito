TARGET = egalito
SOURCES = main.c
OBJECTS = $(SOURCES:.c=.o)

CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lcapstone -Wl,-q

.PHONY: all
all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	-rm $(TARGET) $(OBJECTS)
