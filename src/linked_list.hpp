#include <cstdint>

namespace engine
{
    /* template 'linked_node' */
    template <typename T>
    class linked_node
    {
    public:
        linked_node<T>* last; // 0
        linked_node<T>* next; // 8
    };
}