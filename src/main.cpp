#include <windows.h>
#include <cstdint>
#include <fstream>
#include <filesystem>
#include <map>
#include <string>
#include <vector>
#include <winternl.h>
#include <intrin.h>
#include "minhook.hpp"
#include "memory.hpp"
#include "hook.hpp"
#include "script_var.hpp"
#include "linked_list.hpp"
#include "json.hpp"

/* Link MinHook.lib */
#pragma comment(lib, "MinHook.lib")


std::uintptr_t game_base = (std::uintptr_t)GetModuleHandle(NULL);
HMODULE my_module = NULL;

std::vector<std::string> debug_checks;

std::uintptr_t get_data_section_start(HMODULE module)
{
    /* Get module base */
    std::uintptr_t base = (std::uintptr_t)module;
    /* Get PE header */
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)(base + dos_header->e_lfanew);
    /* Get data section */
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
    /* Check name */
    while (strcmp((char *)section->Name, ".data") != 0)
        section = (PIMAGE_SECTION_HEADER)((std::uintptr_t)section + sizeof(IMAGE_SECTION_HEADER));
    /* Return data section start */
    return base + section->VirtualAddress;
}

std::uintptr_t find_script_variable(std::uintptr_t start, const char *name)
{
    for (std::uintptr_t i = start; i < start + 0x149290; i += 0x8)
    {
        /* Dereference variable at location */
        std::uintptr_t variable = *reinterpret_cast<std::uintptr_t *>(i);
        /* Check if this is a pointer via VirtualQuery */
        MEMORY_BASIC_INFORMATION info;
        VirtualQuery((LPCVOID)variable, &info, sizeof(MEMORY_BASIC_INFORMATION));
        /* Check if this is a pointer */
        if (info.State == MEM_COMMIT && info.Type == MEM_PRIVATE)
        {
            /* Check if this is the variable we are looking for */
            if (strcmp((char *)variable, name) == 0)
                return i;
        }
    }
    return 0;
}

void dump_save(PVOID address, PVOID length)
{
    /* Open 'save_dump.sav' */
    std::ofstream save_dump("save_dump.sav", std::ios::binary);
    /* Write all bytes to save */
    save_dump.write((char *)address, (std::streamsize)length);
    /* Close file */
    save_dump.close();
}

void dump_faction_test()
{
    std::uintptr_t addr = game_base + 0x1C76D08;
    char *buffer = new char[0x100];
    /* Write test.json to buffer */
    memcpy(buffer, "factions.json", 14);
    /* Null terminator */
    buffer[10] = '\0';
    reinterpret_cast<void(__fastcall *)(int, char **)>((PVOID)addr)(1, &buffer);
    /* Free buffer */
    delete[] buffer;
}

void dump_quest_data()
{
    std::uintptr_t addr = game_base + 0x1B7663C;
    const char *buffer = "quest_data.dat";
    reinterpret_cast<void(__fastcall *)(int, const char **)>((PVOID)addr)(1, &buffer);
}

void dump_inventory_dat()
{
    std::uintptr_t addr = game_base + 0x1BECB58;
    const char *buffer = "inventory.dat";
    reinterpret_cast<void(__fastcall *)(int, const char **)>((PVOID)addr)(1, &buffer);
}

void dump_factionmember_single_save()
{
    std::uintptr_t addr = game_base + 0x1C76784;
    const char *buffer = "faction_member_single_save.dat";
    reinterpret_cast<void(__fastcall *)(int, const char **)>((PVOID)addr)(1, &buffer);
}

void dump_all()
{
    std::uintptr_t addr = game_base + 0x1C7709C;
    const char *buffer = "all.dat";
    reinterpret_cast<void(__fastcall *)(int, const char **)>((PVOID)addr)(1, &buffer);
}

void load_save(const char *filename)
{
    std::uintptr_t addr = game_base + 0x1C77070;
    reinterpret_cast<void(__fastcall *)(int, const char **)>((PVOID)addr)(1, &filename);
}

void dump_faction_profile(const char **data)
{
    std::uintptr_t addr = game_base + 0x1C762AC;
    printf("Addr: 0x%p\n", addr);
    reinterpret_cast<void(__fastcall *)(int, const char **)>((PVOID)addr)(2, data);
}

std::uintptr_t veh_addr = 0;

void *original_debug_print = nullptr;
void __fastcall hook_debug_print(const char *category, const char *str, ...)
{
    /* Get return address */
    std::uintptr_t ret = (std::uintptr_t)_ReturnAddress();
    //printf("Return address: 0x%p\n", ret);
    /* Get va args */
    va_list args;
    va_start(args, str);
    /* Print to console */
    if(category)
        printf("%s ", category);
    vprintf(str, args);
    printf("\n");
    va_end(args);
    return;
}

void read_settings(std::string filename)
{
    /* Open and read file */
    std::ifstream file(filename);
    std::string line;
    while (std::getline(file, line))
    {
        /* Find '=' */
        std::size_t pos = line.find('=');
        /* Get next character */
        std::size_t next = pos + 1;
        /* If next character = 0, continue */
        if (line[next] == '0')
            continue;
        /* Get data before '=' */
        std::string data = line.substr(0, pos);
        /* Add to debug checks */
        debug_checks.push_back(data);
    }
}

std::wstring get_string_from_db(int i)
{
    std::uintptr_t db = *(std::uintptr_t *)(game_base + 0x2701720);
    std::uintptr_t func = game_base + 0x23A6A0;
    wchar_t* str = reinterpret_cast<wchar_t*(__fastcall *)(std::uintptr_t, int, int)>(func)(db, i, 0);
    return std::wstring(str);
}

/* VEH */
LONG WINAPI VEHHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    /* Print exception info */
    if(ExceptionInfo->ExceptionRecord->ExceptionAddress == (PVOID)veh_addr)
    {
        char* category = (char*)ExceptionInfo->ContextRecord->Rcx;
        if (strcmp(category, "[LOOT]: ") == 0)
        {
            hook_debug_print((const char*)ExceptionInfo->ContextRecord->Rcx, (const char*)ExceptionInfo->ContextRecord->Rdx, (const char*)ExceptionInfo->ContextRecord->R8,
                (const char*)ExceptionInfo->ContextRecord->R9, *(DWORD64*)(ExceptionInfo->ContextRecord->Rsp + 0x28), *(DWORD64*)(ExceptionInfo->ContextRecord->Rsp + 0x30));
        }
        else
        {
            /* Call 'hook_debug_print' va */
            hook_debug_print((const char*)ExceptionInfo->ContextRecord->Rcx, (const char*)ExceptionInfo->ContextRecord->Rdx, (const char*)ExceptionInfo->ContextRecord->R8,
                (const char*)ExceptionInfo->ContextRecord->R9);
        }
        
        /*  Increment rip by 5 */
        ExceptionInfo->ContextRecord->Rip += 5;
        /* Perform 'mov     [rsp+18h], r8' */
        *(std::uintptr_t *)(ExceptionInfo->ContextRecord->Rsp + 0x18) = ExceptionInfo->ContextRecord->R8;
        /* Continue execution */
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void dump_all_string_lists()
{
    std::uintptr_t start_addr = game_base + 0x1B28C09;
    std::uintptr_t end_addr = game_base + 0x1B399F9;
    std::size_t diff = 0x22;
    const char* sig = "48 89 05";
    /* Create nlohmann::json object */
    nlohmann::json j;

    std::vector<std::string> string_lists;
    while(start_addr < end_addr)
    {
        std::uintptr_t instance = (ptr)(start_addr + *(signed long*)(start_addr + 3) + 7);
        start_addr++;
        printf("Instance: 0x%p\n", instance);
        if(instance)
        {
            std::uintptr_t db = *(std::uintptr_t*)instance;
            if(!db)
            {
                start_addr = Memory::SigScan(sig, start_addr);
                continue;
            }
            const char* db_name = *(const char**)(db + 0x8);
            if(!db_name)
            {
                db_name = "Unknown";
            }
            /* Create key for db */
            j[db_name] = nlohmann::json::array();
            int num_items = *(int*)(db + 0x28);
            std::uintptr_t items = *(std::uintptr_t*)(db + 0x38);
            if(!items)
            {
                start_addr = Memory::SigScan(sig, start_addr);
                continue;
            }
            for(int i = 0; i < num_items; i++)
            {
                std::uintptr_t item = (std::uintptr_t)(items + 40 * i);
                char* str = *(char**)(item + 0x20);
                if(str)
                {
                    char buffer[0x100];
                    sprintf_s(buffer, "%s: %s", db_name, str);
                    string_lists.push_back(std::string(buffer));
                }
            }
        }
        start_addr = Memory::SigScan(sig, start_addr);
    }

    /* Write all strings to file */
    std::ofstream file("lua_string_lists.txt");
    for(auto& str : string_lists)
    {
        file << str << std::endl;
    }
    printf("Done dumping string lists\n");
}

void add_follower()
{
    std::uintptr_t addr = game_base + 0x1C920D4;
    printf("Addr: 0x%p\n", addr);
    printf("This func: 0x%p\n", add_follower);
    MessageBoxA(NULL, "Press OK to add follower", "Add follower", MB_OK);
    reinterpret_cast<void(__fastcall *)()>(addr)();
}

void main_thread()
{
    //dump_all();
    //load_save("all.dat");
    

    /* Allocate console and set stdout*/
    AllocConsole();
    freopen_s((FILE **)stdout, "CONOUT$", "w", stdout);

    //add_follower();
    /* Add VEH */
    PVOID veh = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)VEHHandler);

    std::uintptr_t debug_print = Memory::GetCallAddress("E8 ? ? ? ? 48 83 C3 10 48 8D 54 24 40 48 89 5C 24 30 48 8D 4C 24 30 E8 ? ? ? ? 84 C0 75 AE", "ShadowOfWar.exe");
    printf("0: 0x%p\n", Memory::GetCallAddress("E8 ? ? ? ? 48 8B 57 08 48 8B CE 48 2B 17 48 C1 FA 04", "ShadowOfWar.exe"));
    printf("1: 0x%p\n", Memory::GetCallAddress("E8 ? ? ? ? 48 83 C3 10 48 8D 54 24 40 48 89 5C 24 30 48 8D 4C 24 30 E8 ? ? ? ? 84 C0 75 AE", "ShadowOfWar.exe"));
    printf("2: 0x%p\n", Memory::GetCallAddress("E8 ? ? ? ? EB 34 48 83 7B 30 00", "ShadowOfWar.exe"));
    printf("3: 0x%p\n", Memory::GetCallAddress("E8 ? ? ? ? 48 83 7B 30 00 74 32", "ShadowOfWar.exe"));
    printf("4: 0x%p\n", Memory::SigScan("E8 ? ? ? ? 80 3D ? ? ? ? ? 0F 84 87 00 00 00", "ShadowOfWar.exe"));
    printf("5: 0x%p\n", Memory::GetCallAddress("E8 ? ? ? ? E9 44 01 00 00 41 81 FE 90 AC A7 46", "ShadowOfWar.exe"));
    if (!debug_print)
    {
        printf("Failed to find debug print\n");
        FreeLibraryAndExitThread(my_module, NULL);
        return;
    }

    /* Print first 20 bytes of debug print function */
    printf("Debug print: 0x%p\n", debug_print);
    for (int i = 0; i < 20; i++)
        printf("%02X ", *(std::uint8_t *)(debug_print + i));
    printf("\n");
    //read_settings("debug_checks.txt");

    //debug_checks.push_back("NemesisForge.Debug");
    //debug_checks.push_back("Faction.Debug.ZonePower");
    //debug_checks.push_back("Faction.Debug.Tribe");
    //debug_checks.push_back("Faction.Debug.TraitCatalyst");
    //debug_checks.push_back("Faction.Debug.Reward");
    //debug_checks.push_back("FactionMember.Debug.Resurrection");
    //debug_checks.push_back("Faction.Debug.BundleMgr");

    //*(bool*)(game_base + 0x2A34DB4) = true; // ambush
    *(bool*)(game_base + 0x2A34DA5) = true; // trait catalyst
    *(bool*)(game_base + 0x2A34DB3) = true; // resurrection
    //*(bool*)(game_base + 0x2A34DB8) = true; // tribe
    *(bool*)(game_base + 0x2A34DA7) = true; // faction reward
    *(bool*)(game_base + 0x2A34DAB) = true; // stat query
    //*(bool*)(game_base + 0x2A34DB4) = true; // ambush
    *(bool*)(game_base + 0x2A34DAA) = true; // grunt trait
    *(bool*)(game_base + 0x2A34DB5) = true; // loot
    ////*(bool*)(game_base + 0x2A34DA3) = true; // inventory


    std::uintptr_t script_array = Memory::GetInstanceAddress("48 89 05 ? ? ? ? 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 89 05 ? ? ? ? 48 89 05 ? ? ? ? 48 89 05 ? ? ? ? E8");
    printf("script_array: 0x%p\n", script_array);
    if (!script_array)
    {
        printf("Failed to find script_array!\n");
        FreeLibraryAndExitThread(my_module, NULL);
        return;
    }
    engine::linked_node<engine::script_var> *node = (engine::linked_node<engine::script_var> *)(*(std::uintptr_t *)(script_array + 0x8));

    //*(bool*)(game_base + 0x2A56934) = 1; // always res

    for (int i = 0; i < 800; i++)
    {
        if (!node)
            break;
        engine::script_var *script = (engine::script_var *)((std::uintptr_t)node - 0x28);
        if (script->name)
        {
            /* check if name contains 'debug' case insensitive */
            if (strstr(script->name, ".Debug") || strstr(script->name, "Debug."))
            {
                //printf("0x%p Found %s\n", script, script->name);

                // script->set_bool(false);
                /* Check if name is in 'debug_checks' */
                for (auto &debug_check : debug_checks)
                {
                    if (!strcmp(script->name, debug_check.c_str()))
                    {
                        printf("Set %s\n", debug_check.c_str());
                        script->set_bool(true);
                        break;
                    }
                }
            }
            /* memcmp against debug checks */
            // for (auto &debug_check : debug_checks)
            //{
            //     if (!strcmp(script->name, debug_check.first.c_str()))
            //     {
            //         //printf("Found %s\n", debug_check.first.c_str());
            //         script->set_bool(true);
            //         break;
            //     }
            // }
        }
        node = node->next;
    }
    /* Hook */
    //hook::hook_function((DWORD64)debug_print, (DWORD64)&hook_debug_print, &original_debug_print, 15);

    /* Write 0xCC to debug_print */
    /* VirtualProtect */
    veh_addr = debug_print;
    DWORD old_protect;
    VirtualProtect((PVOID)debug_print, 1, PAGE_EXECUTE_READWRITE, &old_protect);
    *(std::uint8_t *)debug_print = 0xCC;
    /* Restore old protection */
    VirtualProtect((PVOID)debug_print, 1, old_protect, &old_protect);

    /* Wait for insert to be pressed */
    while (!GetAsyncKeyState(VK_INSERT))
        Sleep(100);
    /* Unhook all */
    hook::unhook_all();
    /* Remove VEH */
    RemoveVectoredExceptionHandler(veh);
    /* Exit and free library */
    FreeLibraryAndExitThread(my_module, NULL);
}

/* DllMain */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    /* If not attach */
    if (fdwReason != DLL_PROCESS_ATTACH)
        return TRUE;

    my_module = (HMODULE)hinstDLL;

    /* Create main thread */
    CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)main_thread, NULL, NULL, NULL);

    return TRUE;
}