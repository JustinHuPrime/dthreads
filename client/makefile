# Copyright 2020 Justin Hu
# 
# SPDX-License-Identifier: LGPL-3.0-or-later

# command options
CC := gcc
RM := rm -rf
MV := mv
MKDIR := mkdir -p
DOXYGEN := doxygen
TOUCH := touch
SED := sed
ECHO := echo
PDFLATEX := pdflatex


# File options
SRCDIRPREFIX := src
OBJDIRPREFIX := bin
DEPDIRPREFIX := dependencies
MAINSUFFIX := main
TESTSUFFIX := test
DOCSDIR := docs

# Main file options
SRCDIR := $(SRCDIRPREFIX)/$(MAINSUFFIX)
SRCS := $(shell find -O3 $(SRCDIR) -type f -name '*.c')

OBJDIR := $(OBJDIRPREFIX)/$(MAINSUFFIX)
OBJS := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))

DEPDIR := $(DEPDIRPREFIX)/$(MAINSUFFIX)
DEPS := $(patsubst $(SRCDIR)/%.c,$(DEPDIR)/%.dep,$(SRCS))

# Test file options
TSRCDIR := $(SRCDIRPREFIX)/$(TESTSUFFIX)
TSRCS := $(shell find -O3 $(TSRCDIR) -type f -name '*.c')

TOBJDIR := $(OBJDIRPREFIX)/$(TESTSUFFIX)
TOBJS := $(patsubst $(TSRCDIR)/%.c,$(TOBJDIR)/%.o,$(TSRCS))

TDEPDIR := $(DEPDIRPREFIX)/$(TESTSUFFIX)
TDEPS := $(patsubst $(TSRCDIR)/%.c,$(TDEPDIR)/%.dep,$(TSRCS))


# final executable name
EXENAME := libdthread.so.0.1.0
TEXENAME := dthread-test


# compiler warnings
WARNINGS := -pedantic -pedantic-errors -Wall -Wextra -Wdouble-promotion\
-Winit-self -Wunused -Wswitch-unreachable -Wuninitialized\
-Wstringop-truncation -Wsuggest-attribute=format -Wsuggest-attribute=malloc\
-Wmissing-include-dirs -Wswitch-bool -Wduplicated-branches -Wduplicated-cond\
-Wtrampolines -Wfloat-equal -Wundef -Wunsafe-loop-optimizations\
-Wunused-macros -Wbad-function-cast -Wcast-qual -Wcast-align -Wwrite-strings\
-Wconversion  -Wdate-time -Wjump-misses-init -Wlogical-op -Waggregate-return\
-Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes\
-Wmissing-declarations -Wpacked -Wredundant-decls -Wnested-externs -Winline\
-Winvalid-pch -Wdisabled-optimization -Wstack-protector\
-Wunsuffixed-float-constants

# compiler options
OPTIONS := -std=c18 -m64 -D_POSIX_C_SOURCE=202002L -I$(SRCDIR) $(WARNINGS)\
-fPIC
DEBUGOPTIONS := -Og -ggdb -Wno-unused-parameter
RELEASEOPTIONS := -O3 -D NDEBUG
TOPTIONS := -I$(TSRCDIR)
LIBS :=


.PHONY: debug release clean diagnose docs
.SECONDEXPANSION:
.SUFFIXES:

# entry points
debug: OPTIONS := $(OPTIONS) $(DEBUGOPTIONS)
debug: $(EXENAME) $(TEXENAME) docs
	@$(ECHO) "Running tests"
	@./$(TEXENAME)
	@$(ECHO) "Done building debug!"

release: OPTIONS := $(OPTIONS) $(RELEASEOPTIONS)
release: $(EXENAME) $(TEXENAME)
	@$(ECHO) "Running tests"
	@./$(TEXENAME)
	@$(ECHO) "Done building release!"

docs: $(DOCSDIR)/.timestamp

clean:
	@$(ECHO) "Removing all generated files and folders."
	@$(RM) $(OBJDIRPREFIX) $(DEPDIRPREFIX) $(DOCSDIR) $(EXENAME) $(TEXENAME)


# documentation details
$(DOCSDIR)/.timestamp: $(shell find -O3 $(SRCDIR) -type f -name '*.[ch]')
	@$(ECHO) "Generating documentation"
	@$(DOXYGEN)
	@$(TOUCH) $@


# executable details
$(EXENAME): $(OBJS)
	@$(ECHO) "Linking $@"
	@$(CC) -shared -o $(EXENAME) $(OPTIONS) $(OBJS) $(LIBS)

$(OBJS): $$(patsubst $(OBJDIR)/%.o,$(SRCDIR)/%.c,$$@) $$(patsubst $(OBJDIR)/%.o,$(DEPDIR)/%.dep,$$@) | $$(dir $$@)
	@$(ECHO) "Compiling $@"
	@$(CC) $(OPTIONS) -c $< -o $@

$(DEPS): $$(patsubst $(DEPDIR)/%.dep,$(SRCDIR)/%.c,$$@) | $$(dir $$@)
	@set -e; $(RM) $@; \
	 $(CC) $(OPTIONS) -MM -MT $(patsubst $(DEPDIR)/%.dep,$(OBJDIR)/%.o,$@) $< > $@.$$$$; \
	 $(SED) 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	 $(RM) $@.$$$$


# test details
$(TEXENAME): $(TOBJS) $(OBJS)
	@$(ECHO) "Linking $@"
	@$(CC) -o $(TEXENAME) $(OPTIONS) $(TOPTIONS) $(filter-out %main.o,$(OBJS)) $(TOBJS) $(LIBS)

$(TOBJS): $$(patsubst $(TOBJDIR)/%.o,$(TSRCDIR)/%.c,$$@) $$(patsubst $(TOBJDIR)/%.o,$(TDEPDIR)/%.dep,$$@) | $$(dir $$@)
	@$(ECHO) "Compiling $@"
	@$(CC) $(OPTIONS) $(TOPTIONS) -c $< -o $@

$(TDEPS): $$(patsubst $(TDEPDIR)/%.dep,$(TSRCDIR)/%.c,$$@) | $$(dir $$@)
	@set -e; $(RM) $@; \
	 $(CC) $(OPTIONS) $(TOPTIONS) -MM -MT $(patsubst $(TDEPDIR)/%.dep,$(TOBJDIR)/%.o,$@) $< > $@.$$$$; \
	 $(SED) 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	 $(RM) $@.$$$$


%/:
	@$(MKDIR) $@


-include $(DEPS) $(TDEPS)