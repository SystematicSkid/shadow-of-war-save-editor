#include <Windows.h>
#include <cstdint>
#include <map>

namespace hook
{
    std::map<DWORD64, std::uint8_t*> hooks;
    const size_t shell_size = 12;
    static void construct_shell(uint8_t *shell, DWORD64 target_address)
    {
        shell[0] = 0x48;
        shell[1] = 0xB8;                                     // mov rax,
        memcpy(shell + 2, &target_address, sizeof(DWORD64)); // copy target address
        shell[10] = 0xFF;
        shell[11] = 0xE0; // jmp rax
    }
    static void hook_function(DWORD64 address, DWORD64 callback, PVOID *original, int length)
    {
        /* Copy original bytes */
        std::uint8_t *original_bytes = new std::uint8_t[length];
        memcpy(original_bytes, reinterpret_cast<PVOID>(address), length);
        hooks[address] = original_bytes;
        // Create jmp shellcode to the callback function
        uint8_t callbackShell[shell_size];
        construct_shell(callbackShell, callback);

        // Allocate memory for the trampoline and copy the original bytes
        size_t hookLength = static_cast<size_t>(length);
        PCHAR trampoline = static_cast<PCHAR>(malloc(hookLength + shell_size));
        memcpy(trampoline, reinterpret_cast<PCHAR>(address), hookLength);

        // Create jmp shellcode back to the original function after the hook
        uint8_t trampolineShell[shell_size];
        DWORD64 trampolineAddress = address + hookLength;
        construct_shell(trampolineShell, trampolineAddress);

        // Insert jmp shellcode into trampoline
        memcpy(trampoline + hookLength, trampolineShell, shell_size);
        *original = trampoline;

        // Update protection of trampoline memory to allow execution
        DWORD protection;
        VirtualProtect(trampoline, hookLength + shell_size, PAGE_EXECUTE_READWRITE, &protection);

        // Overwrite original function with jmp shellcode to the callback
        DWORD originalProtection;
        VirtualProtect(reinterpret_cast<PVOID>(address), shell_size, PAGE_EXECUTE_READWRITE, &originalProtection);
        memcpy(reinterpret_cast<PVOID>(address), callbackShell, shell_size);
        VirtualProtect(reinterpret_cast<PVOID>(address), shell_size, originalProtection, &originalProtection);
    }

    static void unhook_all( )
    {
        for (auto& hook : hooks)
        {
            DWORD64 address = hook.first;
            std::uint8_t* original_bytes = hook.second;
            DWORD originalProtection;
            VirtualProtect(reinterpret_cast<PVOID>(address), shell_size, PAGE_EXECUTE_READWRITE, &originalProtection);
            memcpy(reinterpret_cast<PVOID>(address), original_bytes, shell_size);
            VirtualProtect(reinterpret_cast<PVOID>(address), shell_size, originalProtection, &originalProtection);
            delete[] original_bytes;
        }
    }
}