# Makefile for egalito

CC  = gcc
CXX = g++
GENERIC_FLAGS   = -Wall -Wextra -Wno-unused-parameter -I.
OPT_FLAGS       = -g -O2
CFLAGS          = -std=gnu99 $(GENERIC_FLAGS) $(OPT_FLAGS)
CXXFLAGS        = -std=c++11 $(GENERIC_FLAGS) $(OPT_FLAGS)
LDFLAGS         = -lcapstone -Wl,-q

CHUNK_SOURCES       = $(wildcard chunk/*.cpp)
ELF_SOURCES         = $(wildcard elf/*.cpp)
MAIN_SOURCES        = $(wildcard main/*.cpp)
TRANSFORM_SOURCES   = $(wildcard transform/*.cpp)

SOURCES = $(CHUNK_SOURCES) $(ELF_SOURCES) $(MAIN_SOURCES) $(TRANSFORM_SOURCES)
OBJECTS = $(patsubst %.c,%.o,$(patsubst %.cpp,%.o,$(SOURCES:.s=.o)))

TARGET = egalito

# Default target
.PHONY: all
all: $(TARGET)

# Rules
%.o: %.s
	$(CC) -fPIC -c $^ -o $@

# Programs and libraries
$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Other targets
.PHONY: clean
clean:
	-rm $(TARGET) $(OBJECTS)
