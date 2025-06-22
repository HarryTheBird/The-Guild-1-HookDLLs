# Cross-compilation target for Windows 32-bit
TARGET = x86-windows-gnu

# C compiler to use (Zig acting as a C compiler)
CC = zig cc -target $(TARGET)

# Compiler flags
CFLAGS = -Wall -O2

# MinHook paths
MINHOOK_DIR = vendor/minhook
MINHOOK_SRC = $(MINHOOK_DIR)/src
MINHOOK_INC = $(MINHOOK_DIR)/include
MINHOOK_LIB = $(MINHOOK_DIR)/libminhook.a
CFLAGS += -I$(MINHOOK_INC)

# Source files
SRC_DIR = src
BUILD_DIR = build
RELEASE_DIR = release

INJECTOR_SRC = $(SRC_DIR)/injector.c
INJECTOR_EXE = $(BUILD_DIR)/injector.exe

KERNEL32_SRC = $(SRC_DIR)/kernel32_proxy.c
KERNEL32_DLL = $(BUILD_DIR)/hook_kernel32.dll

SERVER_SRC = $(SRC_DIR)/server_proxy.c
SERVER_DLL = $(BUILD_DIR)/hook_server.dll

WS2_32_SRC = $(SRC_DIR)/ws2_32_proxy.c
WS2_32_DLL = $(BUILD_DIR)/hook_ws2_32.dll

# Ensure submodule is initialized and up to date
submodule:
	@git submodule update --init --recursive

# Default target
all: submodule $(INJECTOR_EXE) $(KERNEL32_DLL) $(SERVER_DLL) $(WS2_32_DLL)

# Rule to build the injector
$(INJECTOR_EXE): $(INJECTOR_SRC)
	@echo "Compiling $< -> $@"
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $<

# Rule to build MinHook static library
$(MINHOOK_LIB):
	@echo "Building MinHook static library..."
	zig cc -target $(TARGET) -I$(MINHOOK_INC) -c $(MINHOOK_SRC)/buffer.c -o buffer.o
	zig cc -target $(TARGET) -I$(MINHOOK_INC) -c $(MINHOOK_SRC)/hde/hde32.c -o hde32.o
	zig cc -target $(TARGET) -I$(MINHOOK_INC) -c $(MINHOOK_SRC)/hde/hde64.c -o hde64.o
	zig cc -target $(TARGET) -I$(MINHOOK_INC) -c $(MINHOOK_SRC)/hook.c -o hook.o
	zig cc -target $(TARGET) -I$(MINHOOK_INC) -c $(MINHOOK_SRC)/trampoline.c -o trampoline.o
	ar -rcs $(MINHOOK_LIB) buffer.o hde32.o hde64.o hook.o trampoline.o
	rm buffer.o hde32.o hde64.o hook.o trampoline.o

# Generic rule to build DLLs
$(BUILD_DIR)/hook_%.dll: $(SRC_DIR)/%_proxy.c $(MINHOOK_LIB)
	@echo "Compiling $< -> $@"
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -shared -o $@ $< $(MINHOOK_LIB) -lshlwapi -lws2_32

# Copy artifacts to the release directory
install: all
	@echo "Installing artifacts to $(RELEASE_DIR)..."
	@cp $(INJECTOR_EXE) $(RELEASE_DIR)/
	@mkdir -p $(RELEASE_DIR)/Server
	@cp $(BUILD_DIR)/hook_*.dll $(RELEASE_DIR)/Server/
	@echo "Installation complete."

# Create a distributable zip file
package: install
	@echo "Packaging release into The-Guild-1-HookDLLs.zip..."
	@cd $(RELEASE_DIR) && zip -r ../The-Guild-1-HookDLLs.zip .
	@echo "Packaging complete."

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@rm -f $(RELEASE_DIR)/injector.exe
	@rm -f $(RELEASE_DIR)/Server/hook_*.dll
	@rm -f The-Guild-1-HookDLLs.zip
	@echo "Clean complete."

.PHONY: all clean install package submodule 