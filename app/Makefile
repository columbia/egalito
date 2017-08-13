# Makefile for egalito applications

include ../env.mk

# Dependencies for Python Bindings
BOOST_PYTHON_LIB = boost_python3
PYTHON_LIB = python3.6m
PYTHON_INC_DIR = /usr/include/python3.6m

CFLAGS      += -g -I ../src/
CXXFLAGS    += -g -I ../src/
CLDFLAGS    += -L ../src/$(BUILDDIR) -legalito -Wl,-rpath=../src/$(BUILDDIR)

SHELL_SOURCES       = $(wildcard shell/*.cpp)
PYTHON_SOURCES      = $(wildcard python/*.cpp)

exe-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)))
obj-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)).o)
dep-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)).d)

ETSHELL_SOURCES = $(SHELL_SOURCES)
ETSHELL_OBJECTS = $(call obj-filename,$(ETSHELL_SOURCES))

PYTHON_OBJECTS = $(call obj-filename,$(PYTHON_SOURCES))

ALL_SOURCES = $(sort $(ETSHELL_SOURCES))
ALL_OBJECTS = $(call obj-filename,$(ALL_SOURCES))

BUILDTREE = $(sort $(dir $(ALL_OBJECTS) $(PYTHON_OBJECTS)))

ETSHELL = $(BUILDDIR)etshell
PYTHON_BINDING = $(BUILDDIR)python_egalito.so
PYSHELL = $(BUILDDIR)pyshell

OUTPUTS = $(ETSHELL)

# Default target
.PHONY: all
all: app-all .symlinks

app-all: $(OUTPUTS) | rebuild-src

python: $(BUILDTREE) $(PYTHON_BINDING) $(PYSHELL)
	@ln -sf $(PYSHELL)

ifeq ($(findstring clean,$(MAKECMDGOALS)),)
Makefile: rebuild-src
endif

$(ALL_OBJECTS): | $(BUILDTREE)
$(BUILDTREE): ../config/config.h
	@mkdir -p $@

../config/config.h:
	$(MAKE) -C ../config

.symlinks: $(OUTPUTS)
	@touch .symlinks
	@echo making symlinks...
	@ln -sf $(ETSHELL)

.PHONY: rebuild-src
rebuild-src:
	$(MAKE) -C ../src

# Dependencies
DEPEND_FILES = $(call dep-filename,$(ALL_SOURCES))
-include $(DEPEND_FILES)

# Special files
$(BUILDDIR)python/%.o: python/%.cpp
	$(CXX) $(CXXFLAGS) -I $(PYTHON_INC_DIR) -fPIC $(DEPFLAGS) -c -o $@ $<

$(BUILDDIR)shell/shell.o: shell/shell.cpp
	$(SHORT_CXX) $(CXXFLAGS) $(DEPFLAGS) -DGIT_VERSION=$(shell git rev-parse --short HEAD) -c -o $@ $<

$(PYTHON_BINDING): $(PYTHON_OBJECTS) ../src/$(BUILDDIR)libegalito.a
	$(CXX) $(CXXFLAGS) -fPIC -o $@ $< -l$(BOOST_PYTHON_LIB) -l$(PYTHON_LIB)  $(CLDFLAGS) -shared

# Programs and libraries
$(ETSHELL): $(ETSHELL_OBJECTS)
	$(SHORT_LINK) $(CXXFLAGS) -o $@ $^ $(CLDFLAGS) -lreadline

$(ETSHELL): ../src/$(BUILDDIR)libegalito.so

$(PYSHELL): $(PYTHON_BINDING) python/shell.py
	cp python/shell.py $(BUILDDIR)pyshell
	chmod +x $(BUILDDIR)pyshell

# Other targets
.PHONY: clean realclean
clean:
	-rm -rf $(BUILDDIR) .symlinks etshell pyshell
