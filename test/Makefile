# Makefile for egalito test code

include ../env.mk

CFLAGS      += -I ../src/
CXXFLAGS    += -I ../src/
CLDFLAGS    += -L ../src/$(BUILDDIR) -legalito -Wl,-rpath=../src/$(BUILDDIR)

ANALYSIS_SOURCES    = $(wildcard analysis/*.cpp)
CHUNK_SOURCES       = $(wildcard chunk/*.cpp)
PASS_SOURCES        = $(wildcard pass/*.cpp)
FRAMEWORK_SOURCES   = $(wildcard framework/*.cpp)
INTEGRATION_SOURCES = $(wildcard integration/*.cpp)
ELF_SOURCES         = $(wildcard elf/*.cpp)

exe-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)))
obj-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)).o)
dep-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)).d)

SOURCES = $(INTEGRATION_SOURCES)
ITEST_SOURCES = $(SOURCES) $(INTEGRATION_SOURCES)
ITEST_OBJECTS = $(call obj-filename,$(ITEST_SOURCES))
RUNNER_SOURCES = $(FRAMEWORK_SOURCES) $(CHUNK_SOURCES) $(ANALYSIS_SOURCES) $(PASS_SOURCES) $(ELF_SOURCES)
RUNNER_OBJECTS = $(call obj-filename,$(RUNNER_SOURCES))
ALL_SOURCES = $(sort $(ITEST_SOURCES) $(RUNNER_SOURCES))
ALL_OBJECTS = $(call obj-filename,$(ALL_SOURCES))

BUILDTREE = $(sort $(dir $(ALL_OBJECTS)))

ITEST = $(BUILDDIR)itest
RUNNER = $(BUILDDIR)runner

OUTPUTS = $(ITEST) $(RUNNER)

# Default target
.PHONY: all
all: test-all symlinks

test-all: $(ITEST) $(RUNNER) | rebuild-src

ifeq ($(findstring clean,$(MAKECMDGOALS)),)
Makefile: rebuild-src
endif

$(ALL_OBJECTS): | $(BUILDTREE)
$(BUILDTREE):
	@mkdir -p $@

symlinks: $(OUTPUTS) .symlinks
	@echo making symlinks...
	@ln -sf $(BUILDDIR)itest
	@ln -sf $(BUILDDIR)runner

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

# Programs and libraries
$(ITEST): $(ITEST_OBJECTS) ../src/libegalito.a
	$(CXX) $(CXXFLAGS) -o $@ $^ $(CLDFLAGS)
$(RUNNER): $(RUNNER_OBJECTS) ../src/libegalito.a
	$(CXX) $(CXXFLAGS) -o $@ $^ $(CLDFLAGS)

# Other targets
.PHONY: clean realclean
clean:
	-rm -f .symlinks itest runner
	-find $(BUILDDIR) -name framework -prune -o -type f -exec rm {} \;

realclean:
	-rm -rf $(BUILDDIR) .symlinks itest runner
