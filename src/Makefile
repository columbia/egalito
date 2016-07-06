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
TRANSFORM_SOURCES   = $(wildcard transform/*.cpp)
LOAD_SOURCES        = $(wildcard load/*.cpp)
MAIN_SOURCES        = $(wildcard main/*.cpp)

SOURCES = $(CHUNK_SOURCES) $(ELF_SOURCES) $(TRANSFORM_SOURCES)
TARGET_SOURCES = $(SOURCES) $(MAIN_SOURCES)
TARGET_OBJECTS = $(patsubst %.c,%.o,$(patsubst %.cpp,%.o,$(TARGET_SOURCES:.s=.o)))
LOADER_SOURCES = $(SOURCES) $(LOAD_SOURCES)
LOADER_OBJECTS = $(patsubst %.c,%.o,$(patsubst %.cpp,%.o,$(LOADER_SOURCES:.s=.o)))

TARGET = egalito
LOADER = loader

# Default target
.PHONY: all
all: $(TARGET) $(LOADER)

# Rules
%.o: %.s
	$(CC) -fPIC -c $^ -o $@

# Programs and libraries
$(TARGET): $(TARGET_OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
$(LOADER): $(LOADER_OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) -static -Wl,-Ttext-segment=0x7400000 -Wl,-Trodata-segment=0x7600000

# Other targets
.PHONY: clean
clean:
	-rm $(TARGET) $(LOADER) $(OBJECTS)
