#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <chrono>
#include <map>
#include <fstream>
#include <sstream>
#include <thread>
#include <mutex>
#include <atomic>

struct PatternInfo {
    std::string pattern;
    std::string name;
};

HANDLE hProcess = nullptr;
uintptr_t baseAddress = 0;
SIZE_T baseSize = 0;
std::mutex memoryMutex;
constexpr SIZE_T mrc = 0x400000;
constexpr auto rst = std::chrono::milliseconds(200);
constexpr auto pst = std::chrono::seconds(5);

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

bool HasReadableProtection(DWORD protect) {
    constexpr DWORD readableProtections =
        PAGE_READONLY |
        PAGE_READWRITE |
        PAGE_EXECUTE_READ |
        PAGE_EXECUTE_READWRITE;
    return (protect & readableProtections) != 0;
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

bool attach(DWORD pid, const std::string& moduleName) {
    std::lock_guard<std::mutex> lock(memoryMutex);
    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION, NULL, pid);
    if (!hProcess) {
        std::cerr << "[-] Failed to open process. Error: " << GetLastError() << "\n";
        return false;
    }
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH] = { 0 };
            if (GetModuleBaseNameA(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(char))) {
                if (_stricmp(szModName, moduleName.c_str()) == 0) {
                    MODULEINFO modInfo = { 0 };
                    if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                        baseAddress = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
                        baseSize = modInfo.SizeOfImage;
                        std::cout << "[+] Attached to module: " << szModName << "\n";
                        std::cout << "[+] Base Address: 0x" << std::hex << baseAddress << ", Size: 0x"
                            << baseSize << std::dec << "\n";
                        return true;
                    }
                }
            }
        }
    }
    std::cerr << "[-] Module not found: " << moduleName << "\n";
    return false;
}

std::pair<std::vector<char>, std::string> hexStringToPattern(const std::string& hexPattern) {
    std::vector<char> bytes;
    std::string mask;
    std::istringstream stream(hexPattern);
    std::string byteString;

    while (stream >> byteString) {
        if (byteString == "?") {
            bytes.push_back(0x00); 
            mask += '?';
        }
        else {
            bytes.push_back(static_cast<char>(strtol(byteString.c_str(), nullptr, 16)));
            mask += 'x';
        }
    }
    return { bytes, mask };
}

uintptr_t fastfindPattern(const std::string& hexPattern, bool extractOffset = false, const std::string& OffsetType = "dword") {
    auto [pattern, mask] = hexStringToPattern(hexPattern);
    if (pattern.empty() || pattern.size() != mask.size() || pattern.size() < 1) return 0; // Handles tiny patterns

    HANDLE hProc = hProcess;
    if (!hProc || hProc == INVALID_HANDLE_VALUE) return 0;

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    uintptr_t min = reinterpret_cast<uintptr_t>(sysInfo.lpMinimumApplicationAddress);
    uintptr_t max = reinterpret_cast<uintptr_t>(sysInfo.lpMaximumApplicationAddress);

    MEMORY_BASIC_INFORMATION mbi;
    std::vector<char> buffer;

    while (true) {
        for (uintptr_t addr = min; addr < max; addr += mbi.RegionSize) {
            if (!VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi)))
                continue;

            if (mbi.State != MEM_COMMIT || !(mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
                continue;

            SIZE_T size = mbi.RegionSize;
            buffer.resize(size);
            SIZE_T bytesRead;

            if (!ReadProcessMemory(hProc, (LPCVOID)mbi.BaseAddress, buffer.data(), size, &bytesRead))
                continue;

            const size_t plen = pattern.size();
            if (plen > bytesRead) continue;

            for (size_t i = 0; i <= bytesRead - plen; ++i) {
                bool match = true;

                for (size_t j = 0; j < plen; ++j) {
                    if (mask[j] == 'x' && buffer[i + j] != pattern[j]) {
                        match = false;
                        break;
                    }
                }

                if (match) {
                    uintptr_t result = (uintptr_t)mbi.BaseAddress + i;

                    if (extractOffset) {
                        int32_t rel = 0;
                        uintptr_t offsetAddr = result + 3;

                        if (!ReadProcessMemory(hProc, (LPCVOID)offsetAddr, &rel, sizeof(rel), nullptr))
                            continue;

                        uintptr_t finalOffset = (OffsetType == "byte")
                            ? result + rel + 7
                            : offsetAddr + rel + sizeof(rel);

                        if (finalOffset >= min && finalOffset < max)
                            return finalOffset;
                    }
                    else {
                        return result;
                    }
                }
            }
        }

        Sleep(1); 
    }
}

bool attach(DWORD pid, const std::string& moduleName) {
    std::lock_guard<std::mutex> lock(memoryMutex);
    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION, NULL, pid);
    if (!hProcess) {
        std::cerr << "[-] Failed to open process. Error: " << GetLastError() << "\n";
        return false;
    }
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH] = { 0 };
            if (GetModuleBaseNameA(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(char))) {
                if (_stricmp(szModName, moduleName.c_str()) == 0) {
                    MODULEINFO modInfo = { 0 };
                    if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                        baseAddress = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
                        baseSize = modInfo.SizeOfImage;
                        std::cout << "[+] Attached to module: " << szModName << "\n";
                        std::cout << "[+] Base Address: 0x" << std::hex << baseAddress << ", Size: 0x"
                            << baseSize << std::dec << "\n";
                        return true;
                    }
                }
            }
        }
    }
    std::cerr << "[-] Module not found: " << moduleName << "\n";
    return false;
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
    if (!attach(pid, "RobloxPlayerBeta.exe")) {
        std::cerr << "Failed to attach to process." << std::endl;
        system("pause");
        return 1;
    }

    uintptr_t moduleBase = baseAddress;
    SIZE_T moduleSize = baseSize;

    std::vector<PatternInfo> patterns = {
        {"48 83 EC ? 44 8B C2 48 8B D1 48 8D 4C 24", "luaD_throw"},
        {"48 8B C4 44 89 48 20 4C 89 40 18 48 89 50 10 48 89 48 08 53", "ScriptContextResume"},
        {"4C 38 02 8E FC 34 0C 70 00 1B A2 28 6C 6A 62 42 22 16 2A 53 0B 46 03 B0 C2 BC 36 7B 7C 63 32 90 20 3E 84 27 56 3B 58 DE BE 3C 7A 68 13 3F 50 5E CC 9C 66 D2 E2 8A B6 51 61 44 3A 52 23 4A 5F E1", "OpcodeLookupTable"},
        {"48 89 54 24 10 4C 89 44 24 18 4C 89 4C 24 20 55", "rbx_print"},
        {"4C 8D 0D ? ? ? ? 4D 8B 0C C1", "KTable"},
    };

    uintptr_t startAddress = moduleBase;
    uintptr_t endAddress = moduleBase + moduleSize;

    MEMORY_BASIC_INFORMATION memInfo;
    bool foundAny = false;

    for (const auto& patternInfo : patterns) {
        if (patternInfo.name == "KTable") {
            uintptr_t ktableResult = fastfindPattern(patternInfo.pattern, true, "unk");
            if (ktableResult) {
                std::cout << "[" << patternInfo.name << "] Pattern found at address: 0x"
                    << std::hex << ktableResult << " (offset: 0x" << (ktableResult - moduleBase) << ")" << std::dec << std::endl;
                foundAny = true;
                continue;
            }
        }

        std::vector<BYTE> patternBytes;
        std::string mask;
        if (!PatternToBytes(patternInfo.pattern, patternBytes, mask)) {
            std::cerr << "Failed to parse pattern for " << patternInfo.name << std::endl;
            continue;
        }

        uintptr_t currentAddress = startAddress;
        bool foundPattern = false;
        size_t regionsScanned = 0;
        auto patternStartTime = std::chrono::steady_clock::now();
        bool patternTimeoutReached = false;

        while (currentAddress < endAddress && !foundPattern && !patternTimeoutReached) {
            if (VirtualQueryEx(hProcess, (LPCVOID)currentAddress, &memInfo, sizeof(memInfo)) == sizeof(memInfo)) {
                regionsScanned++;

                if ((memInfo.State == MEM_COMMIT) &&
                    !(memInfo.Protect & PAGE_GUARD) &&
                    !(memInfo.Protect & PAGE_NOACCESS) &&
                    memInfo.BaseAddress >= (LPCVOID)startAddress &&
                    (uintptr_t)memInfo.BaseAddress < endAddress) {

                    if (!HasReadableProtection(memInfo.Protect)) {
                        std::cerr << "[Skipped] Region at 0x" << std::hex << (uintptr_t)memInfo.BaseAddress
                            << " has unsupported protections (0x" << memInfo.Protect << ")" << std::dec << std::endl;
                        currentAddress = (uintptr_t)memInfo.BaseAddress + memInfo.RegionSize;
                        continue;
                    }

                    uintptr_t regionStart = (uintptr_t)memInfo.BaseAddress;
                    SIZE_T regionSize = memInfo.RegionSize;

                    if (regionStart + regionSize > endAddress) {
                        regionSize = endAddress - regionStart;
                    }

                    uintptr_t regionEnd = regionStart + regionSize;
                    uintptr_t chunkAddress = regionStart;

                    while (chunkAddress < regionEnd && !foundPattern && !patternTimeoutReached) {
                        SIZE_T chunkSize = static_cast<SIZE_T>(std::min<uintptr_t>(mrc, regionEnd - chunkAddress));
                        auto chunkStartTime = std::chrono::steady_clock::now();
                        uintptr_t found = ScanRegion(hProcess, chunkAddress, chunkSize, patternBytes, mask);
                        auto chunkDuration = std::chrono::steady_clock::now() - chunkStartTime;
                        auto chunkDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(chunkDuration).count();

                        if (chunkDuration > rst) {
                            std::cerr << "[Warning] Region chunk at 0x" << std::hex << chunkAddress
                                << " took " << chunkDurationMs << " ms (" << chunkSize << " bytes)" << std::dec << std::endl;
                        }

                        if (found) {
                            uintptr_t offset = found - moduleBase;
                            std::cout << "[" << patternInfo.name << "] Pattern found at address: 0x"
                                << std::hex << found << " (offset: 0x" << offset << ")" << std::dec << std::endl;
                            foundPattern = true;
                            foundAny = true;
                            break;
                        }

                        chunkAddress += chunkSize;

                        auto totalPatternTime = std::chrono::steady_clock::now() - patternStartTime;
                        if (totalPatternTime > pst) {
                            auto totalMs = std::chrono::duration_cast<std::chrono::milliseconds>(totalPatternTime).count();
                            std::cerr << "[Timeout] Pattern \"" << patternInfo.name << "\" scanning took "
                                << totalMs << " ms, aborting remaining regions." << std::endl;
                            patternTimeoutReached = true;
                        }
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
