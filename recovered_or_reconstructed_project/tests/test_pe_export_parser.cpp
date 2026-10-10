#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cassert>
#include <vector>

// Standalone cross-platform implementation of the PE export parser from 0x00411ff0 (FindExportRvaInFile)
#pragma pack(push, 1)
struct DosHeader {
    uint16_t e_magic;
    uint8_t  e_cblp[58];
    uint32_t e_lfanew;
};

struct FileHeader {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct SectionHeader {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint8_t  unused[16];
};

struct ExportDirectory {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
};
#pragma pack(pop)

uint32_t rva2off(const std::vector<SectionHeader>& sections, uint32_t rva) {
    for (const auto& sec : sections) {
        if (rva >= sec.VirtualAddress && rva < sec.VirtualAddress + sec.VirtualSize) {
            return (rva - sec.VirtualAddress) + sec.PointerToRawData;
        }
    }
    return 0;
}

bool findExportRva(const uint8_t* pBase, size_t fileSize, const char* targetExport, uint32_t* outRva) {
    if (fileSize < sizeof(DosHeader)) return false;
    const DosHeader* dos = (const DosHeader*)pBase;
    if (dos->e_magic != 0x5A4D) return false;

    if (dos->e_lfanew + 4 + sizeof(FileHeader) > fileSize) return false;
    const uint8_t* nt = pBase + dos->e_lfanew;
    if (*(const uint32_t*)nt != 0x00004550) return false;

    const FileHeader* fh = (const FileHeader*)(nt + 4);
    const uint8_t* opt = nt + 4 + sizeof(FileHeader);
    uint16_t optMagic = *(const uint16_t*)opt;

    uint32_t exportDirRva = 0;
    if (optMagic == 0x10b) { // PE32
        exportDirRva = *(const uint32_t*)(opt + 0x60);
    } else if (optMagic == 0x20b) { // PE32+
        exportDirRva = *(const uint32_t*)(opt + 0x70);
    }

    if (!exportDirRva) return false;

    const SectionHeader* secArr = (const SectionHeader*)(opt + fh->SizeOfOptionalHeader);
    std::vector<SectionHeader> sections(secArr, secArr + fh->NumberOfSections);

    uint32_t exportDirOff = rva2off(sections, exportDirRva);
    if (!exportDirOff || exportDirOff + sizeof(ExportDirectory) > fileSize) return false;

    const ExportDirectory* expDir = (const ExportDirectory*)(pBase + exportDirOff);
    uint32_t namesOff = rva2off(sections, expDir->AddressOfNames);
    uint32_t funcsOff = rva2off(sections, expDir->AddressOfFunctions);
    uint32_t ordsOff  = rva2off(sections, expDir->AddressOfNameOrdinals);

    if (!namesOff || !funcsOff || !ordsOff) return false;

    const uint32_t* nameRvas = (const uint32_t*)(pBase + namesOff);
    const uint32_t* funcRvas = (const uint32_t*)(pBase + funcsOff);
    const uint16_t* ordinals  = (const uint16_t*)(pBase + ordsOff);

    for (uint32_t i = 0; i < expDir->NumberOfNames; i++) {
        uint32_t nameOff = rva2off(sections, nameRvas[i]);
        if (nameOff && nameOff < fileSize) {
            const char* name = (const char*)(pBase + nameOff);
            if (strcmp(name, targetExport) == 0) {
                uint16_t ord = ordinals[i];
                *outRva = funcRvas[ord];
                return true;
            }
        }
    }
    return false;
}

int main() {
    printf("[*] Running test_pe_export_parser against working/NRTH.dll...\n");
    FILE* fp = fopen("working/NRTH.dll", "rb");
    assert(fp != nullptr);

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    std::vector<uint8_t> buffer(size);
    assert(fread(buffer.data(), 1, size, fp) == (size_t)size);
    fclose(fp);

    uint32_t rva = 0;
    bool found = findExportRva(buffer.data(), buffer.size(), "NVXHookProc", &rva);
    assert(found);
    printf("  [+] Located export 'NVXHookProc' at RVA: 0x%08X (Expected: 0x0000B9E0)\n", rva);
    assert(rva == 0x0000B9E0);

    // Negative test: non-existent export
    bool foundInvalid = findExportRva(buffer.data(), buffer.size(), "NonExistentExport", &rva);
    assert(!foundInvalid);
    printf("  [+] Negative test passed: Non-existent export safely returns false.\n");

    printf("[+] All PE export parser tests passed successfully!\n");
    return 0;
}
