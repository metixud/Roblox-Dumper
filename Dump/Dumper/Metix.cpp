#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <string>
// made by ducks / updated by metix
struct PatternInfo {
    std::string pattern;
    std::string name;
};

bool PatternToBytes(const std::string& pattern, std::vector<BYTE>& bytes, std::string& mask) {
    bytes.clear();
    mask.clear();

    size_t i = 0;
    while (i < pattern.size()) {
        if (pattern[i] == ' ') {
            i++;
            continue;
        }
        if (pattern[i] == '?') {
            bytes.push_back(0x00);
            mask += '?';
            i++;
            if (i < pattern.size() && pattern[i] == '?') i++;
        }
        else {
            if (i + 1 >= pattern.size()) return false;
            auto hexCharToInt = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                else if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                else if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
                };
            int high = hexCharToInt(pattern[i]);
            int low = hexCharToInt(pattern[i + 1]);
            if (high == -1 || low == -1) return false;
            bytes.push_back((BYTE)((high << 4) | low));
            mask += 'x';
            i += 2;
        }
    }
    return true;
}

bool DataCompare(const BYTE* data, const BYTE* pattern, const std::string& mask, size_t size) {
    for (size_t i = 0; i < size; i++) {
        if (mask[i] == 'x' && data[i] != pattern[i])
            return false;
    }
    return true;
}

uintptr_t ScanRegion(HANDLE hProcess, uintptr_t base, size_t size, const std::vector<BYTE>& pattern, const std::string& mask) {
    std::vector<BYTE> buffer(size);
    SIZE_T bytesRead;

    if (!ReadProcessMemory(hProcess, (LPCVOID)base, buffer.data(), size, &bytesRead) || bytesRead < pattern.size()) {
        return 0;
    }

    for (size_t i = 0; i <= bytesRead - pattern.size(); i++) {
        if (DataCompare(buffer.data() + i, pattern.data(), mask, pattern.size())) {
            return base + i;
        }
    }
    return 0;
}

DWORD GetProcessIdByName(const std::wstring& processName) {
    DWORD processId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (processName == entry.szExeFile) {
                processId = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return processId;
}

uintptr_t GetModuleBaseAddress(DWORD pid, const std::wstring& moduleName) {
    uintptr_t baseAddress = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32W);

    if (Module32FirstW(snapshot, &moduleEntry)) {
        do {
            if (moduleName == moduleEntry.szModule) {
                baseAddress = (uintptr_t)moduleEntry.modBaseAddr;
                break;
            }
        } while (Module32NextW(snapshot, &moduleEntry));
    }
    CloseHandle(snapshot);
    return baseAddress;
}

SIZE_T GetModuleSize(DWORD pid, const std::wstring& moduleName) {
    SIZE_T moduleSize = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32W);

    if (Module32FirstW(snapshot, &moduleEntry)) {
        do {
            if (moduleName == moduleEntry.szModule) {
                moduleSize = moduleEntry.modBaseSize;
                break;
            }
        } while (Module32NextW(snapshot, &moduleEntry));
    }
    CloseHandle(snapshot);
    return moduleSize;
}

int main() {
    std::wstring targetProcessName = L"RobloxPlayerBeta.exe";
    DWORD pid = GetProcessIdByName(targetProcessName);
    if (!pid) {
        std::cerr << "Roblox process not found." << std::endl;
        system("pause");
        return 1;
    }
    std::cout << "Roblox PID: " << pid << std::endl;

    uintptr_t moduleBase = GetModuleBaseAddress(pid, targetProcessName);
    if (!moduleBase) {
        std::cerr << "Failed to get module base address." << std::endl;
        system("pause");
        return 1;
    }
    std::cout << "Module Base Address: 0x" << std::hex << moduleBase << std::dec << std::endl;

    SIZE_T moduleSize = GetModuleSize(pid, targetProcessName);
    if (moduleSize == 0) {
        std::cerr << "Failed to get module size." << std::endl;
        system("pause");
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Failed to open Roblox process." << std::endl;
        system("pause");
        return 1;
    }

    std::vector<PatternInfo> patterns = {
        {"48 83 EC ? 44 8B C2 48 8B D1 48 8D 4C 24", "luaD_throw"},
        {"48 8B C4 44 89 48 20 4C 89 40 18 48 89 50 10 48 89 48 08 53", "ScriptContextResume"},
        {"3E 52 54", "OpcodeLookupTable"},

    };

    uintptr_t startAddress = moduleBase;
    uintptr_t endAddress = moduleBase + moduleSize;

    MEMORY_BASIC_INFORMATION memInfo;
    bool foundAny = false;

    for (const auto& patternInfo : patterns) {
        std::vector<BYTE> patternBytes;
        std::string mask;
        if (!PatternToBytes(patternInfo.pattern, patternBytes, mask)) {
            std::cerr << "Failed to parse pattern for " << patternInfo.name << std::endl;
            continue;
        }

        uintptr_t currentAddress = startAddress;
        bool foundPattern = false;
        size_t regionsScanned = 0;

        while (currentAddress < endAddress) {
            if (VirtualQueryEx(hProcess, (LPCVOID)currentAddress, &memInfo, sizeof(memInfo)) == sizeof(memInfo)) {
                regionsScanned++;

                if ((memInfo.State == MEM_COMMIT) &&
                    !(memInfo.Protect & PAGE_GUARD) &&
                    !(memInfo.Protect & PAGE_NOACCESS) &&
                    memInfo.BaseAddress >= (LPCVOID)startAddress &&
                    (uintptr_t)memInfo.BaseAddress < endAddress) {

                    uintptr_t regionStart = (uintptr_t)memInfo.BaseAddress;
                    SIZE_T regionSize = memInfo.RegionSize;

                    if (regionStart + regionSize > endAddress) {
                        regionSize = endAddress - regionStart;
                    }

                    uintptr_t found = ScanRegion(hProcess, regionStart, regionSize, patternBytes, mask);
                    if (found) {
                        uintptr_t offset = found - moduleBase;
                        std::cout << "[" << patternInfo.name << "] Pattern found at address: 0x"
                            << std::hex << found << " (offset: 0x" << offset << ")" << std::dec << std::endl;
                        foundPattern = true;
                        foundAny = true;
                        break;
                    }
                }
                currentAddress = (uintptr_t)memInfo.BaseAddress + memInfo.RegionSize;
            }
            else {
                break;
            }
        }

        if (!foundPattern) {
            std::cout << "[" << patternInfo.name << "] Pattern not found after scanning " << regionsScanned << " regions." << std::endl;
        }
    }

    CloseHandle(hProcess);
    system("pause");
    return 0;
}
