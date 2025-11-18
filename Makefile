CC := gcc
CFLAGS := -fPIC -Wall -Wextra -O2
LDFLAGS := -shared

LIB_DIR := lib
BIN_DIR := bin

LIB_NAME := mylib
# Place the built shared library into the bin directory so the executable and
# library live side-by-side.
LIB_OUT_DIR := $(BIN_DIR)
LIB_SO := $(LIB_OUT_DIR)/lib$(LIB_NAME).so
MAIN_BIN := $(BIN_DIR)/airlock_ctrl

.PHONY: all clean

all: $(LIB_SO) $(MAIN_BIN)

$(LIB_SO): $(LIB_DIR)/mylib.c $(LIB_DIR)/mylib.h
	@mkdir -p $(LIB_OUT_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(LIB_DIR)/mylib.c

$(MAIN_BIN): src/main.c $(LIB_SO)
	@mkdir -p $(BIN_DIR)
	# Link against the library placed inside $(LIB_OUT_DIR) and set rpath
	# so the loader will search the executable's directory at runtime.
	$(CC) $(CFLAGS) -I$(LIB_DIR) -o $@ src/main.c -L$(LIB_OUT_DIR) -l$(LIB_NAME) -Wl,-rpath,'$$ORIGIN'

clean:
	rm -rf $(BIN_DIR)
