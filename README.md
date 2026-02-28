# roblox offsets dumper ( pattern scanner )

scans the memory of a running roblox process and looks for byte patterns inside the main module. prints the address and offset of each match.

originally by **ducks**, updated by **metix**.

---

## what it does

- finds the roblox process by name (`RobloxPlayerBeta.exe`)
- gets the base address and size of the main module
- walks through all committed, readable memory regions
- for each pattern, scans region by region and prints the result

currently shipped with two patterns:
`luaD_throw`
`OpcodeLookupTable` 

---

## requirements
- visual studio or any msvc-compatible compiler
- roblox must be running before you launch the scanner

---

## build

open in visual studio, make sure you're targeting x64, then build and run.

## usage

1. launch roblox
2. run the compiled binary as **administrator**
3. output will look like:

```
Roblox PID: 12345
Module Base Address: 0x0
[luaD_throw] Pattern found at address: 0x0 (offset: 0x0)
[OpcodeLookupTable] Pattern found at address: 0x0 (offset: 0x0)
```

if a pattern isn't found it'll tell you how many regions it scanned.

---

## adding patterns

in `main()`, add an entry to the `patterns` vector:

```cpp
{"48 89 5C 24 ? 57 48 83 EC 20", "myFunction"},
```

use `??` or `?` for wildcard bytes.

---

## notes

- patterns break on roblox updates, you'll need to rescan and update them
- run as admin or `OpenProcess` / `ReadProcessMemory` will fail
- only scans `MEM_COMMIT` regions, skips `PAGE_GUARD` and `PAGE_NOACCESS`
