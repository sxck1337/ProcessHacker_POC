#include "driver/driver.hpp"
#include "ext/helpers.hpp"

int main()
{
    printf( "PH-Client starting..\n" );

    if (!Driver::Connect( ))
    {
        printf( "couldn't connect to driver...\n" );
        return 1;
    }

    printf( "driver connected!\n" );
    printf( "provide pid:\n" );

    int pid;
    std::cin >> pid;

    if (!Driver::Attach( pid ))
    {
        printf( "couldn't attach to process...\n" );
        return 1;
    }

    uintptr_t cave_off = Driver::FindCodeCave( "Test.exe", 200 );
    if (cave_off != NULL)
    {
        uintptr_t cave = Driver::GetModuleBase( "Test.exe" ) + cave_off;
        NTSTATUS write_res = Driver::Write<int>( (PVOID)cave, 1337 );
        printf( "cave write: 0x%x\n", write_res );

        int read_res = Driver::Read<int>( (PVOID)cave );
        printf( "cave read: %d\n", read_res );
    }
    
    Driver::Detach( );

    printf( "finished...\n" );
    return 0;
}
