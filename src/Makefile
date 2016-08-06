# Makefile for egalito

CC  = gcc
CXX = g++
GENERIC_FLAGS   = -Wall -Wextra -Wno-unused-parameter -I.
OPT_FLAGS       = -g -O2
CFLAGS          = -std=gnu99 $(GENERIC_FLAGS) $(OPT_FLAGS)
CXXFLAGS        = -std=c++11 $(GENERIC_FLAGS) $(OPT_FLAGS)
CLDFLAGS        = -lcapstone -Wl,-q
LDFLAGS         = -lcapstone -q
#LDFLAGS2        = `gcc --print-file-name=libstdc++.a` `gcc --print-file-name=libgcc.a`
LDFLAGS2        = $(shell g++ -print-search-dirs 2>&1 | grep libraries | sed 's/libraries: =/:/; s/:/ -L/g') -lstdc++ --start-group -lgcc -lgcc_eh -lc --end-group

GLIBCDIR = /usr/lib/x86_64-linux-gnu
#STARTFILES = $(GLIBCDIR)/crt1.o $(GLIBCDIR)/crti.o `gcc --print-file-name=crtbeginT.o`
STARTFILES = $(GLIBCDIR)/crti.o `gcc --print-file-name=crtbegin.o`
ENDFILES = `gcc --print-file-name=crtend.o` $(GLIBCDIR)/crtn.o

BREAK_SOURCES       = $(wildcard break/*.cpp)
CHUNK_SOURCES       = $(wildcard chunk/*.cpp)
ELF_SOURCES         = $(wildcard elf/*.cpp)
TRANSFORM_SOURCES   = $(wildcard transform/*.cpp)
LOAD_SOURCES        = $(wildcard load/*.cpp) load/bootstrap.s
LOG_SOURCES         = $(wildcard log/*.cpp)
MAIN_SOURCES        = $(wildcard main/*.cpp)

SOURCES = $(CHUNK_SOURCES) $(ELF_SOURCES) $(TRANSFORM_SOURCES) $(LOG_SOURCES)
TARGET_SOURCES = $(SOURCES) $(MAIN_SOURCES)
TARGET_OBJECTS = $(patsubst %.c,%.o,$(patsubst %.cpp,%.o,$(TARGET_SOURCES:.s=.o)))
LOADER_SOURCES = $(SOURCES) $(BREAK_SOURCES) $(LOAD_SOURCES)
LOADER_OBJECTS = $(patsubst %.c,%.o,$(patsubst %.cpp,%.o,$(LOADER_SOURCES:.s=.o)))
ALL_SOURCES = $(TARGET_SOURCES) $(LOADER_SOURCES)

TARGET = egalito
LOADER = loader

# Default target
.PHONY: all
all: $(TARGET) $(LOADER)

# Dependencies
-include depend
depend: $(ALL_SOURCES) $(shell find -name '*.h')
	@echo '# generating dependencies'
	-@$(RM) depend
	@bash -c 'for file in $(filter %.cpp,$(ALL_SOURCES)); do \
		$(CXX) $(CXXFLAGS) -MM -MT $${file/.cpp/.o} $$file >> depend ; \
	done'

# Rules
%.o: %.s
	$(CC) -fPIC -c $^ -o $@
%.o: %.c
	$(CC) $(CFLAGS) -DDEBUG=D_$(shell echo $< | perl -ne 's|/|_|g;s/\.c$$//;print uc') -c -o $@ $<
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -DDEBUG=D_$(shell echo $< | perl -ne 's|/|_|g;s/\.cpp$$//;print uc') -c -o $@ $<

# Programs and libraries
$(TARGET): $(TARGET_OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(CLDFLAGS) -v
$(LOADER): $(LOADER_OBJECTS)
	$(CXX) -static -o $@ \
        -nostartfiles $(STARTFILES) $^ $(CLDFLAGS) $(ENDFILES) -Wl,--eh-frame-hdr \
        -Wl,-Ttext-segment=0x7400000 -Wl,-Trodata-segment=0x7600000
	#$(LD) --eh-frame-hdr -static -o $@ $(STARTFILES) $^ -lc $(LDFLAGS) $(LDFLAGS2) $(ENDFILES) \
    #    -Ttext-segment=0x7400000 -Trodata-segment=0x7600000

# Other targets
.PHONY: clean
clean:
	-rm $(TARGET) $(LOADER) $(TARGET_OBJECTS) $(LOADER_OBJECTS)
