# Makefile for egalito applications

include ../env.mk

CFLAGS      += -g -I ../src/
CXXFLAGS    += -g -I ../src/
CLDFLAGS    += -L ../src/$(BUILDDIR) -legalito -Wl,-rpath=../src/$(BUILDDIR)

SHELL_SOURCES       = $(wildcard shell/*.cpp)
PYTHON_SOURCES = $(wildcard python/*.cpp)

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

OUTPUTS = $(ETSHELL) $(PYTHON_BINDING) $(PYSHELL)

# Default target
.PHONY: all
all: app-all symlinks

app-all: $(OUTPUTS) | rebuild-src

ifeq ($(findstring clean,$(MAKECMDGOALS)),)
Makefile: rebuild-src
endif

$(ALL_OBJECTS): | $(BUILDTREE)
$(BUILDTREE):
	@mkdir -p $@

symlinks: $(OUTPUTS) .symlinks
	@echo making symlinks...
	@ln -sf $(ETSHELL)
	@ln -sf $(PYSHELL)

.symlinks:
	@touch .symlinks

.PHONY: relink
relink: symlinks

.PHONY: rebuild-src
rebuild-src:
	$(MAKE) -C ../src

# Dependencies
DEPEND_FILES = $(call dep-filename,$(ALL_SOURCES))
-include $(DEPEND_FILES)

# Rules
$(BUILDDIR)%.o: %.s
	$(CC) -fPIC -c $< -o $@
$(BUILDDIR)%.o: %.S
	$(CC) -fPIC $(DEPFLAGS) -c $< -o $@
$(BUILDDIR)%.o: %.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DDEBUG_GROUP=$(shell echo $< | perl -ne 'm|^(\w+)/|g;print lc($$1)') -c -o $@ $<
$(BUILDDIR)%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(DEPFLAGS) -DDEBUG_GROUP=$(shell echo $< | perl -ne 'm|^(\w+)/|g;print lc($$1)') -c -o $@ $<

# Special files
$(BUILDDIR)python/%.o: python/%.cpp
	$(CXX) $(CXXFLAGS) -I /usr/include/python3.6m -fPIC $(DEPFLAGS) -c -o $@ $<

$(BUILDDIR)shell/shell.o: shell/shell.cpp
	$(CXX) $(CXXFLAGS) $(DEPFLAGS) -DGIT_VERSION=$(shell git rev-parse --short HEAD) -c -o $@ $<

$(PYTHON_BINDING): $(PYTHON_OBJECTS)
	$(CXX) $(CXXFLAGS) -fPIC -o $@ $^ -lboost_python3 -lpython3.6m  $(CLDFLAGS) -shared

# Programs and libraries
$(ETSHELL): $(ETSHELL_OBJECTS) ../src/libegalito.a
	$(CXX) $(CXXFLAGS) -o $@ $^ $(CLDFLAGS) -lreadline

$(PYSHELL): $(PYTHON_BINDING)
	cp python/shell.py $(BUILDDIR)pyshell
	chmod +x $(BUILDDIR)pyshell

# Other targets
.PHONY: clean realclean
clean:
	-rm -rf $(BUILDDIR) .symlinks etshell pyshell
