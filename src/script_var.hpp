#include <cstdint>
#include <Windows.h>

namespace engine
{
    class script_var
    {
    public:
        PVOID vtable; // 0
        PCHAR name; // 8
        PCHAR description; // 10
        PCHAR file; // 18
        INT32 line; // 20
        void set_bool(bool value) // 38
        {
            *(bool*)((std::uintptr_t)this + 0x38) = value;
        }
    };
}