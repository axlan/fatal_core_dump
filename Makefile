CC := gcc
# Build mode: release (default) or debug
MODE ?= debug

# Base flags shared across modes
CFLAGS_BASE := -fPIC -Wall -Wextra

ifeq ($(MODE),debug)
# Debug mode: no optimizations, include debug symbols
CFLAGS := $(CFLAGS_BASE) -O0 -g -fcf-protection=none -z execstack -DAPP_DEBUG_BUILD=1
else
# Release mode: optimize
CFLAGS := $(CFLAGS_BASE) -O2
endif

LDFLAGS := -shared

LIB_DIR := lib
BIN_DIR := bin

# Libraries to build (each corresponds to lib/<name>.c and lib/<name>.h)
LIB_NAMES := sdn_interface config_loader log

# Place the built shared libraries into the bin directory so the executable and
# libraries live side-by-side.
LIB_OUT_DIR := $(BIN_DIR)
LIB_SOS := $(patsubst %,$(LIB_OUT_DIR)/lib%.so,$(LIB_NAMES))
MAIN_BIN := $(BIN_DIR)/airlock_ctrl
POC_BIN := $(BIN_DIR)/min_poc

.PHONY: all clean

.PHONY: debug release
# Convenience targets (invoke make with MODE so prerequisites see it)
debug:
	$(MAKE) MODE=debug all

release:
	$(MAKE) MODE=release all


# all: build all shared libs and the main binary
all: $(LIB_SOS) $(MAIN_BIN) $(POC_BIN)

# Generic rule: build a shared library from lib/<name>.c (and optional .h)
$(LIB_OUT_DIR)/lib%.so: $(LIB_DIR)/%.c $(LIB_DIR)/%.h
	@mkdir -p $(LIB_OUT_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(LIB_DIR)/$*.c

# If header is optional for a library (no .h), allow building from .c only
$(LIB_OUT_DIR)/lib%.so: $(LIB_DIR)/%.c
	@mkdir -p $(LIB_OUT_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(LIB_DIR)/$*.c

$(MAIN_BIN): src/main.c $(LIB_SOS)
	@mkdir -p $(BIN_DIR)
	# Link against the library placed inside $(LIB_OUT_DIR) and set rpath
	# so the loader will search the executable's directory at runtime.
	$(CC) $(CFLAGS) -I$(LIB_DIR) -o $@ src/main.c -L$(LIB_OUT_DIR) $(foreach L,$(LIB_NAMES),-l$(L)) -Wl,-rpath,'$$ORIGIN'

$(POC_BIN): minimal_example/min_poc.c $(LIB_SOS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -I$(LIB_DIR) -o $@ minimal_example/min_poc.c -L$(LIB_OUT_DIR) $(foreach L,$(LIB_NAMES),-l$(L)) -Wl,-rpath,'$$ORIGIN'


clean:
	rm -rf $(BIN_DIR)
