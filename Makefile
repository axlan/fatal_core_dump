CC := gcc
# Build mode: release (default) or debug
MODE ?= release

# Base flags shared across modes
CFLAGS_BASE := -fPIC -Wall -Wextra

ifeq ($(MODE),debug)
# Debug mode: no optimizations, include debug symbols and enable ENABLE_LOG_DEBUG macro
CFLAGS := $(CFLAGS_BASE) -O0 -g -DENABLE_LOG_DEBUG
else
# Release mode: optimize
CFLAGS := $(CFLAGS_BASE) -O2
endif

LDFLAGS := -shared

LIB_DIR := lib
BIN_DIR := bin

# Primary library built from lib/sdn_interface.c
SDN_LIB_NAME := sdn_interface
# Additional dynamic library for configuration loader
CONFIG_LIB_NAME := config_loader
# Place the built shared library into the bin directory so the executable and
# library live side-by-side.
LIB_OUT_DIR := $(BIN_DIR)
SDN_LIB_SO := $(LIB_OUT_DIR)/lib$(SDN_LIB_NAME).so
CONFIG_LIB_SO := $(LIB_OUT_DIR)/lib$(CONFIG_LIB_NAME).so
MAIN_BIN := $(BIN_DIR)/airlock_ctrl

.PHONY: all clean

.PHONY: debug release
# Convenience targets (invoke make with MODE so prerequisites see it)
debug:
	$(MAKE) MODE=debug all

release:
	$(MAKE) MODE=release all

all: $(SDN_LIB_SO) $(CONFIG_LIB_SO) $(MAIN_BIN)

$(SDN_LIB_SO): $(LIB_DIR)/sdn_interface.c $(LIB_DIR)/sdn_interface.h
	@mkdir -p $(LIB_OUT_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(LIB_DIR)/sdn_interface.c

$(CONFIG_LIB_SO): $(LIB_DIR)/config_loader.c $(LIB_DIR)/config_loader.h
	@mkdir -p $(LIB_OUT_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(LIB_DIR)/config_loader.c

$(MAIN_BIN): src/main.c $(SDN_LIB_SO) $(CONFIG_LIB_SO)
	@mkdir -p $(BIN_DIR)
	# Link against the library placed inside $(LIB_OUT_DIR) and set rpath
	# so the loader will search the executable's directory at runtime.
	$(CC) $(CFLAGS) -I$(LIB_DIR) -o $@ src/main.c -L$(LIB_OUT_DIR) -l$(SDN_LIB_NAME) -l$(CONFIG_LIB_NAME) -Wl,-rpath,'$$ORIGIN'

clean:
	rm -rf $(BIN_DIR)
