# Makefile for egalito applications

include ../env.mk

CFLAGS      += -I ../src/
CXXFLAGS    += -I ../src/
CLDFLAGS    += -L ../src/$(BUILDDIR) -legalito -Wl,-rpath=../src/$(BUILDDIR)

SHELL_SOURCES       = $(wildcard shell/*.cpp)

exe-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)))
obj-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)).o)
dep-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)).d)

ETSHELL_SOURCES = $(SHELL_SOURCES)
ETSHELL_OBJECTS = $(call obj-filename,$(ETSHELL_SOURCES))
ALL_SOURCES = $(sort $(ETSHELL_SOURCES))
ALL_OBJECTS = $(call obj-filename,$(ALL_SOURCES))

BUILDTREE = $(sort $(dir $(ALL_OBJECTS)))

ETSHELL = $(BUILDDIR)etshell

OUTPUTS = $(ETSHELL)

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
	@ln -sf $(BUILDDIR)etshell

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
$(BUILDDIR)shell/shell.o: shell/shell.cpp
	$(CXX) $(CXXFLAGS) $(DEPFLAGS) -DGIT_VERSION=$(shell git rev-parse --short HEAD) -c -o $@ $<

# Programs and libraries
$(ETSHELL): $(ETSHELL_OBJECTS) ../src/libegalito.a
	$(CXX) $(CXXFLAGS) -o $@ $^ $(CLDFLAGS) -lreadline

# Other targets
.PHONY: clean realclean
clean:
	-rm -rf $(BUILDDIR) .symlinks etshell
