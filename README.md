AIHL - Android Import Hook Library
==================================

AIHL is a library for hooking into standard library function by modifying android linkers symbol tables. This library was created as a way to enable hooking of native library functions from within xposed modules.

AIHL allows the modification of the symbol pointers in the android linker so that any **subsequently** loaded libraries or `dlsym` calls will use the hooked functions instead of the real function. It is optionally possible to call through to the original function if needed.

One of the restriction of this method is that only subsequently loaded libraries are affected unlike [other][1] [hooking][2] libraries.

The library is provided as a static library, but the two code files `aihl.c` and `aihl.h` could easily be included directly in your make file if needed.

Example
-------

    #include <aihl.h>
    
    int hooked_stat(const char *path, struct stat *st) {
        printf("Inside hooked stat\n");
        
        //call original stat function
	    return stat(path, st);
    }
    
    void hook() {
        aihl_hook_symbol("libc.so", "stat", hooked_stat);
    }

>This library works under the assumption that the internal info structure used by the android linker does not change or is changed in a backward compatible format. This may not be a safe assumption. The code was successfully tested with cyanogenmod version 10.1 and 11.

[1]:https://github.com/crmulliner/adbi
[2]:https://github.com/shoumikhin/ELF-Hook/

License
-------
Apache License

