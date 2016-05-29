# Makefile for egalito

CC  = gcc
CXX = g++
CFLAGS      = -Wall -Wextra
CXXFLAGS    = -std=c++11 -Wall -Wextra -I. -g -O2
LDFLAGS     = -lcapstone -Wl,-q

CHUNK_SOURCES       = $(wildcard chunk/*.cpp)
ELF_SOURCES         = $(wildcard elf/*.cpp)
MAIN_SOURCES        = $(wildcard main/*.c)
TRANSFORM_SOURCES   = $(wildcard transform/*.cpp)

SOURCES = $(CHUNK_SOURCES) $(ELF_SOURCES) $(MAIN_SOURCES) $(TRANSFORM_SOURCES)
OBJECTS = $(patsubst %.cpp,%.o,$(SOURCES:.s=.o))

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
