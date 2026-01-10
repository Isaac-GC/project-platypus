# JNI Bridge handler

To use:
1. Pull the necessary libraries from an AOSP image (or build them directly through AOSP sources)
   1. See below for the recommended libraries
2. Load them with `load_elf_library`
3. Should be able to run/execute code as if you were actually on the device

    
### Libraries
- `/system/lib64/libc.so`
- `/system/lib64/libm.so`
- `/system/lib64/libdl.so`
- `/system/lib64/liblog.so`
- `/system/lib64/libz.so`
- `/system/lib64/libutils.so`
- `/system/lib64/libcutils.so`


### TODOs
- Convert library from python to rust
  - Make it standalone lib rather than a requirement