# Makefile for egalito test code

include ../../env.mk

CFLAGS      += -I ../../src/
CXXFLAGS    += -I ../../src/

FRAMEWORK_SOURCES   = $(wildcard *.cpp)

exe-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)))
obj-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)).o)
dep-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)).d)

LIBFRAMEWORK_SOURCES = $(FRAMEWORK_SOURCES)
LIBFRAMEWORK_OBJECTS = $(call obj-filename,$(LIBFRAMEWORK_SOURCES))
ALL_SOURCES = $(sort $(LIBFRAMEWORK_SOURCES))
ALL_OBJECTS = $(call obj-filename,$(ALL_SOURCES))

BUILDTREE = $(sort $(dir $(ALL_OBJECTS)))

LIBFRAMEWORK = $(BUILDDIR)libframework.a

OUTPUTS = $(LIBFRAMEWORK)

# Default target
.PHONY: all
all: $(OUTPUTS) .symlinks
	@true

$(ALL_OBJECTS): | $(BUILDTREE)
$(BUILDTREE):
	@mkdir -p $@

.symlinks: $(OUTPUTS)
	@touch .symlinks
	@echo "LN-S" $(OUTPUTS)
	@ln -sf $(BUILDDIR)libframework.a

# Dependencies
DEPEND_FILES = $(call dep-filename,$(ALL_SOURCES))
-include $(DEPEND_FILES)

# Programs and libraries
$(LIBFRAMEWORK): $(LIBFRAMEWORK_OBJECTS)
	$(SHORT_AR) cr $@ $^

# Other targets
.PHONY: clean realclean
clean:
	-rm -f .symlinks libframework.a $(LIBFRAMEWORK)

realclean:
	-rm -rf $(BUILDDIR) .symlinks libframework.a
