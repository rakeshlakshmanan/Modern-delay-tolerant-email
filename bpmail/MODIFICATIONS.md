# BPMail Modifications

This is a modified version of BPMail (https://github.com/250MHz/bpmail)
adapted for compilation with ION-DTN 4.1.4 on Ubuntu 22.04 (ARM64/aarch64).

## Changes from upstream

1. **meson.build**: Changed `c_std=c17` to `c_std=gnu17`.
   - Reason: ION's platform.h uses `#ifdef linux` to define MAXPATHLEN.
     Strict C17 mode disables the `linux` platform macro even when `-Dlinux`
     is passed, causing a MAXPATHLEN compilation error. GNU C17 preserves
     the platform macro while remaining C17-compliant.

2. **linux-native.txt**: Added native build file with `c_args = ['-Dlinux']`.
   - Reason: Ensures the `-Dlinux` flag is passed during compilation so ION
     headers correctly resolve platform-specific definitions.

## Build instructions

    meson setup build --native-file linux-native.txt
    ninja -C build
    sudo ninja -C build install

## Runtime note

After installation, ensure the linker uses the manually compiled c-ares
(1.34.4) rather than the system version:

    sudo ldconfig /usr/local/lib
