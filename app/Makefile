# Makefile for egalito applications

include ../env.mk

# Dependencies for Python Bindings
BOOST_PYTHON_LIB = boost_python3
PYTHON_LIB = python3.6m
PYTHON_INC_DIR = /usr/include/python3.6m

CFLAGS      += -g -I ../src/
CXXFLAGS    += -g -I ../src/
CLDFLAGS    += -L ../src/$(BUILDDIR) -legalito \
	-Wl,-rpath=$(abspath ../src/$(BUILDDIR)) \
	-Wl,-rpath=$(abspath ../dep/capstone/install/lib)

SANDBOX_SOURCES         = $(wildcard sandbox/*.c sandbox/*.cpp)
SANDBOX_INJECT_SOURCES  = $(wildcard sandbox/inject/*.c sandbox/inject/*.cpp)
CET_SOURCES             = $(wildcard cet/*.c cet/*.cpp)
CET_INJECT_SOURCES      = $(wildcard cet/inject/*.c cet/inject/*.cpp)
SHELL_SOURCES           = $(wildcard shell/*.cpp)
OBJDUMP_SOURCES         = $(wildcard objdump/*.cpp)
PYTHON_SOURCES          = $(wildcard python/*.cpp)

exe-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)))
obj-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)).o)
dep-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)).d)

ETSHELL_SOURCES = $(SHELL_SOURCES)
ETSHELL_OBJECTS = $(call obj-filename,$(ETSHELL_SOURCES))
ETOBJDUMP_SOURCES = $(OBJDUMP_SOURCES)
ETOBJDUMP_OBJECTS = $(call obj-filename,$(ETOBJDUMP_SOURCES))
ETSANDBOX_SOURCES = $(SANDBOX_SOURCES)
ETSANDBOX_OBJECTS = $(call obj-filename,$(ETSANDBOX_SOURCES))
ETCET_SOURCES = $(CET_SOURCES)
ETCET_OBJECTS = $(call obj-filename,$(ETCET_SOURCES))
LIBSANDBOX_SOURCES = $(SANDBOX_INJECT_SOURCES)
LIBSANDBOX_OBJECTS = $(call obj-filename,$(LIBSANDBOX_SOURCES))
LIBCET_SOURCES = $(CET_INJECT_SOURCES)
LIBCET_OBJECTS = $(call obj-filename,$(LIBCET_SOURCES))

ALL_SOURCES = $(sort $(ETSHELL_SOURCES) $(ETOBJDUMP_SOURCES) \
    $(ETSANDBOX_SOURCES) $(LIBSANDBOX_SOURCES) \
    $(ETCET_SOURCES) $(LIBCET_SOURCES))
ALL_OBJECTS = $(call obj-filename,$(ALL_SOURCES))

PYTHON_OBJECTS = $(call obj-filename,$(PYTHON_SOURCES))
BUILDTREE = $(sort $(dir $(ALL_OBJECTS) $(PYTHON_OBJECTS)))

ETSHELL = $(BUILDDIR)etshell
ETOBJDUMP = $(BUILDDIR)etobjdump
ETSANDBOX = $(BUILDDIR)etsandbox
ETCET = $(BUILDDIR)etcet
PYTHON_BINDING = $(BUILDDIR)python_egalito.so
PYSHELL = $(BUILDDIR)pyshell
SANDBOX_LIBRARY = $(BUILDDIR)libsandbox.so
CET_LIBRARY = $(BUILDDIR)libcet.so

OUTPUTS = $(ETSHELL) $(ETOBJDUMP) $(ETSANDBOX) $(SANDBOX_LIBRARY) $(ETCET) $(CET_LIBRARY)

# Default target
.PHONY: all
all: app-all .symlinks
	@true

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
	$(call short-make,../config)

.symlinks: $(OUTPUTS)
	@touch .symlinks
	@echo "LN-S" $(OUTPUTS)
	@ln -sf $(ETSHELL)
	@ln -sf $(ETOBJDUMP)
	@ln -sf $(ETSANDBOX)
	@ln -sf $(SANDBOX_LIBRARY)
	@ln -sf $(ETCET)
	@ln -sf $(CET_LIBRARY)
	@ln -sf $(shell pwd)/../src/$(BUILDDIR)libegalito.so $(BUILDDIR)libegalito.so

.PHONY: rebuild-src
rebuild-src:
	$(call short-make,../src)

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
	$(SHORT_LINK) $(CXXFLAGS) -o $@ $^ $(CLDFLAGS) -lreadline -Wl,-rpath=$(abspath ../src)
$(ETSHELL): ../src/$(BUILDDIR)libegalito.so

$(ETOBJDUMP): $(ETOBJDUMP_OBJECTS)
	$(SHORT_LINK) $(CXXFLAGS) -o $@ $^ $(CLDFLAGS) -Wl,-rpath=$(abspath ../src)
$(ETOBJDUMP): ../src/$(BUILDDIR)libegalito.so

$(ETSANDBOX): $(ETSANDBOX_OBJECTS)
	$(SHORT_LINK) $(CXXFLAGS) -o $@ $^ $(CLDFLAGS) -Wl,-rpath=$(abspath ../src)
$(ETSANDBOX): ../src/$(BUILDDIR)libegalito.so

$(ETCET): $(ETCET_OBJECTS)
	$(SHORT_LINK) $(CXXFLAGS) -o $@ $^ $(CLDFLAGS) -Wl,-rpath=$(abspath ../src)
$(ETCET): ../src/$(BUILDDIR)libegalito.so

$(PYSHELL): $(PYTHON_BINDING) python/shell.py
	cp python/shell.py $(BUILDDIR)pyshell
	chmod +x $(BUILDDIR)pyshell

$(SANDBOX_LIBRARY): $(LIBSANDBOX_OBJECTS)
	$(SHORT_LINK) -shared -fPIC -Wl,-soname,libsandbox.so $^ -o $@

$(CET_LIBRARY): $(LIBCET_OBJECTS)
	$(SHORT_LINK) -shared -fPIC -Wl,-soname,libcet.so $^ -o $@

# Other targets
.PHONY: clean realclean
clean:
	-rm -rf $(BUILDDIR) .symlinks etshell pyshell etobjdump etsandbox libsandbox.so etcet libcet.so
