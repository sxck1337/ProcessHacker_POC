#pragma once

#include <Windows.h>
#include <string>
#include <iostream>
#include <winternl.h>
#include <ntstatus.h>

#include "../ext/types.hpp"

enum IO_CODES : ULONG
{
	I_ReadVirtual				= 0x999920e3,
	I_WriteVirtual				= 0x999920e7,
	I_OpenProcess				= 0x999920cb,
	I_QueryInformationObject	= 0x9999225f
};

class Driver
{
public:
	static bool Connect(  );
	static HANDLE GetHandle( );
	static HANDLE GetProcess( );

	static bool Attach( uint32_t pid, ACCESS_MASK access = PROCESS_ALL_ACCESS );
	static bool Detach( );

	template <typename T>
	static inline T Read( PVOID base_address, SIZE_T size = sizeof( T ), PSIZE_T bytes_read = nullptr )
	{
		T ret{};
		PH_VIRTUAL_MEMORY_INPUT data{ m_Process, base_address, &ret, size, bytes_read };

		NTSTATUS status = RWPM( &data, IO_CODES::I_ReadVirtual );
		if (status != STATUS_SUCCESS)
			return T{};

		return ret;
	}

	template <typename T>
	static inline NTSTATUS Write( PVOID base_address, T buffer, SIZE_T size = sizeof( T ), PSIZE_T bytes_written = nullptr )
	{
		PH_VIRTUAL_MEMORY_INPUT data{ m_Process, base_address, &buffer, size, bytes_written };
		return RWPM( &data, IO_CODES::I_WriteVirtual );
	}

	static NTSTATUS QueryInformationObject( PVOID object_info, ULONG object_size, PH_OBJECT_INFO_CLASS object_class );
	static uintptr_t GetModuleBase( std::string module_name );
	static uintptr_t FindCodeCave( std::string module_name, DWORD_PTR cave_size );

private:
	static NTSTATUS RWPM( PH_VIRTUAL_MEMORY_INPUT* data, IO_CODES code );

	static HANDLE			m_Handle;
	static std::string		m_Device;
	static HANDLE			m_Process;
};