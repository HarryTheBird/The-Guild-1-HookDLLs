# The Guild 1 HookDLLs

This project provides a set of hook-DLLs and an injector to patch and stabilize the multiplayer experience in **Europa 1400: The Guild Gold Edition** ("The Guild 1").

## What is this and why?

**The Guild Gold Edition** has a network multiplayer mode that relies on `server.dll` for all network communication. Unfortunately, the original implementation is extremely sensitive to even minor packet loss or timing issues, causing frequent "out of sync" errors and disconnects—especially when playing over VPNs (like Hamachi, Radmin, or TeamViewer) or anything other than a direct LAN connection.

This project was created to fix those issues by intercepting and patching the problematic network routines. It does so by providing replacement DLLs ("hook-DLLs") for `kernel32.dll` and `ws2_32.dll`, as well as a patched `server.dll` and an injector. These DLLs use [MinHook](https://github.com/TsudaKageyu/minhook) to hook and modify the behavior of critical functions, improving network stability and making multiplayer possible even over VPN.

### Technical background
- The original `server.dll` expects perfect packet delivery and will desync or crash on any network hiccup.
- The hook-DLLs intercept calls to Windows APIs (like those in `ws2_32.dll` and `kernel32.dll`) and patch or work around the problematic logic.
- This approach was inspired by community research and reverse engineering.
- The solution is non-invasive: if you want to revert, just remove the DLLs and injector.

## Who is this for?
- Fans of The Guild Gold Edition who want to play multiplayer reliably, even over VPN.
- Modders and tinkerers interested in reverse engineering or improving classic games.
- Anyone who wants to understand or extend the network logic of The Guild 1.

## Features
- DLL hooks for `kernel32`, `ws2_32`, and `server` modules
- Standalone DLL injector
- Clean, reproducible cross-platform build system
- MinHook vendored as a submodule and built from source

## Requirements
- [Zig](https://ziglang.org/) (tested with Zig 0.11+)
- `ar` and `zip` utilities (for packaging)
- Git (for submodules)

## Getting Started

1. **Clone the repository and initialize submodules:**
   ```sh
   git clone https://github.com/yourusername/The-Guild-1-HookDLLs.git
   cd The-Guild-1-HookDLLs
   git submodule update --init --recursive
   ```

2. **Build everything:**
   ```sh
   make all
   ```

3. **Create a distributable package:**
   ```sh
   make package
   ```
   This will create `The-Guild-1-HookDLLs.zip` containing all release artifacts.

4. **Clean build artifacts:**
   ```sh
   make clean
   ```

## Makefile Targets
- `make all`      — Build all DLLs and the injector
- `make install`  — Copy artifacts to the `release/` directory
- `make package`  — Create a zip file for distribution
- `make clean`    — Remove all build and release artifacts

## Directory Structure
- `src/`           — Source code for hooks and injector
- `vendor/minhook/`— MinHook source (as a git submodule)
- `build/`         — Build artifacts (ignored by git)
- `release/`       — Final DLLs, injector, and packaging scripts

## Notes
- All DLLs are cross-compiled for Windows (x86) from Linux.
- MinHook is built from source automatically; no CMake required.
- If you update MinHook, re-run `git submodule update --remote` and rebuild.

## DLL Export Definition Files (.def)
- The `docs/kernel32.def` and `docs/ws2_32.def` files list the exports of the original Windows DLLs (`kernel32.dll`, `ws2_32.dll`).
- These are provided for reference, to help you match the exports in your proxy DLLs if needed.
- If you want your proxy DLLs to export the same functions as the originals, use these files as a template for your own `.def` files or for linker configuration.

## How to use

1. **Build and package the project:**
   - Run `make package` to produce `The-Guild-1-HookDLLs.zip` in the project root.
   - Unzip this file. Inside the `release/` directory, you'll find the DLLs and the injector executable.

2. **Prepare the game:**
   - Make a backup of your original `kernel32.dll` and `ws2_32.dll` in the game directory (if present).
   - Place the built proxy DLLs (`hook_kernel32.dll`, `hook_ws2_32.dll`, etc.) into the game directory, renaming them to match the original DLL names if you want to directly replace them, or use them as side-loaded hooks.

3. **Using the Injector:**
   - Run `injector.exe` with the path to the game executable and the DLLs you want to inject. For example:
     ```sh
     injector.exe "C:\Path\To\Guild.exe" hook_server.dll hook_ws2_32.dll hook_kernel32.dll
     ```
   - The injector can also attach to a running process by PID if needed.

4. **Start the game:**
   - Launch the game as usual, or use the injector to start it in a suspended state and inject the hooks before resuming.

**Note:**
- Some anti-cheat or DRM systems may detect DLL injection as suspicious. Use responsibly and always keep backups of original game files.
- For advanced usage (e.g., custom exports, debugging), refer to the `.def` files in `docs/` and adjust your build or injection process as needed.
- If you encounter issues, simply remove the DLLs and injector to restore the original game state.

## More background
- The multiplayer instability in The Guild 1 is due to the lack of packet loss handling in the original `server.dll`.
- This project was inspired by community guides and reverse engineering efforts (see Steam guides by Atexer and lycanthrope).
- The hook-DLLs and injector are a "drop-in" patch: no installation required, just copy the files and play.
- If you want to contribute, improve, or extend the patch, see the source code and documentation in this repository. 