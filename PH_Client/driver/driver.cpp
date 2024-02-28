#include "driver.hpp"

#include "../ext/helpers.hpp"

HANDLE				Driver::m_Handle = nullptr;
std::string			Driver::m_Device = "\\Device\\KProcessHacker2";

HANDLE				Driver::m_Process = nullptr;

bool Driver::Connect( )
{
	Helpers::SetPrivilege(SE_DEBUG_NAME, TRUE);

	m_Handle = CreateFileA( m_Device.c_str( ), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );
	if (m_Handle != INVALID_HANDLE_VALUE)
		return true;

	UNICODE_STRING objectName;
	OBJECT_ATTRIBUTES objectAttributes;
	IO_STATUS_BLOCK isb;

	RtlInitUnicodeString( &objectName, Helpers::wString( m_Device ).c_str( ) );
	InitializeObjectAttributes( &objectAttributes, &objectName, FILE_NON_DIRECTORY_FILE, NULL, NULL );

	NTSTATUS status = NtOpenFile( &m_Handle, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &objectAttributes, &isb, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_NON_DIRECTORY_FILE );
	if (status != STATUS_SUCCESS)
		return false;

	return true;
}

HANDLE Driver::GetHandle( )
{
	return m_Handle;
}

HANDLE Driver::GetProcess( )
{
	return m_Process;
}

bool Driver::Attach( uint32_t pid, ACCESS_MASK access )
{
	if (!m_Handle)
		return false;

	if (m_Process && !CloseHandle( m_Process ))
		return false;

	PH_CLIENT client{};
	client.UniqueProcess = (HANDLE)pid;
	client.UniqueThread = NULL;

	PH_OPEN_PROCESS_INPUT data{};
	data.ProcessHandle = &m_Process;
	data.DesiredAccess = access;
	data.ClientId = &client;

	IO_STATUS_BLOCK isb;
	NTSTATUS status = NtDeviceIoControlFile( m_Handle, nullptr, nullptr, nullptr, &isb, IO_CODES::I_OpenProcess, &data, sizeof( data ), nullptr, 0 );
	if (status != STATUS_SUCCESS && m_Process != nullptr)
	{
		m_Handle = nullptr;
		return false;
	}

	return true;
}

bool Driver::Detach( )
{
	if (m_Process && !CloseHandle( m_Process ))
		return false;

	m_Process = nullptr;
	return true;
}

NTSTATUS Driver::RWPM( PH_VIRTUAL_MEMORY_INPUT* data, IO_CODES code )
{
	if (!m_Handle || !m_Process)
		return 0x1337;

	IO_STATUS_BLOCK isb;
	return NtDeviceIoControlFile( m_Handle, nullptr, nullptr, nullptr, &isb, code, data, sizeof( PH_VIRTUAL_MEMORY_INPUT ), nullptr, 0 );
}

NTSTATUS Driver::QueryInformationObject( PVOID object_info, ULONG object_size, PH_OBJECT_INFO_CLASS object_class )
{
	if (!m_Handle || !m_Process)
		return 0x1337;

	HANDLE own_handle = OpenProcess( PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId( ) );

	IO_STATUS_BLOCK isb;
	PH_OBJECT_INFO_INPUT data{ own_handle, m_Process, object_class, object_info, object_size, nullptr };
	NTSTATUS status = NtDeviceIoControlFile( m_Handle, nullptr, nullptr, nullptr, &isb, IO_CODES::I_QueryInformationObject, &data, sizeof( PH_OBJECT_INFO_INPUT ), nullptr, 0 );

	CloseHandle( own_handle );
	return status;
}

uintptr_t Driver::GetModuleBase( std::string module_name )
{
	if (!m_Handle || !m_Process)
		return NULL;

	PROCESS_BASIC_INFORMATION basicInfo;
	NTSTATUS status = QueryInformationObject( &basicInfo, sizeof( PROCESS_BASIC_INFORMATION ), PH_OBJECT_INFO_CLASS::PHObjectProcessBasicInformation );
	if (status != STATUS_SUCCESS)
		return NULL;

	MY_PEB peb = Read<MY_PEB>( basicInfo.PebBaseAddress );
	if (!peb.Ldr)
		return NULL;

	MY_PEB_LDR_DATA ldr = Read<MY_PEB_LDR_DATA>( peb.Ldr );
	if (!ldr.InLoadOrderModuleList.Flink)
		return NULL;

	for (MY_LDR_DATA_TABLE_ENTRY dte = Read<MY_LDR_DATA_TABLE_ENTRY>( ldr.InLoadOrderModuleList.Flink ); dte.DllBase != nullptr; dte = Read<MY_LDR_DATA_TABLE_ENTRY>( dte.InLoadOrderLinks.Flink ))
	{
		wchar_t name_buffer[64 * sizeof( wchar_t )];

		PH_VIRTUAL_MEMORY_INPUT data{ m_Process, dte.BaseDllName.Buffer, &name_buffer, 64 * sizeof( wchar_t ), nullptr };
		NTSTATUS status = RWPM( &data, IO_CODES::I_ReadVirtual );
		if (status != STATUS_SUCCESS)
			continue;

		std::wstring base_name( name_buffer, dte.BaseDllName.Length / sizeof( wchar_t ) );
		if (wcscmp( base_name.c_str( ), Helpers::wString( module_name ).c_str( ) ) == 0)
			return reinterpret_cast<uintptr_t>(dte.DllBase);

	}

	return NULL;
}

uintptr_t Driver::FindCodeCave( std::string module_name, DWORD_PTR cave_size )
{
	uintptr_t hModule = GetModuleBase( module_name );

	IMAGE_DOS_HEADER DOSHeader = Read<IMAGE_DOS_HEADER>( reinterpret_cast<PVOID>( hModule ) );
	IMAGE_NT_HEADERS64* pNTHeader = reinterpret_cast<IMAGE_NT_HEADERS64*>(hModule + DOSHeader.e_lfanew);
	IMAGE_NT_HEADERS64 NTHeader = Read<IMAGE_NT_HEADERS64>( pNTHeader );
	IMAGE_SECTION_HEADER* pImageSectionHeader = (IMAGE_SECTION_HEADER*)((DWORD_PTR)pNTHeader + 4 + sizeof( IMAGE_FILE_HEADER ) + NTHeader.FileHeader.SizeOfOptionalHeader);

	if (NTHeader.Signature != IMAGE_NT_SIGNATURE)
	{
		printf( "invalid PE image %u\n", NTHeader.Signature );
		return NULL;
	}

	for (int i = 0; i < NTHeader.FileHeader.NumberOfSections; i++)
	{
		IMAGE_SECTION_HEADER ImageSectionHeader = Read<IMAGE_SECTION_HEADER>( pImageSectionHeader );

		DWORD_PTR SectionSize = ImageSectionHeader.SizeOfRawData;
		BYTE* pSectionData = (BYTE*)(hModule + ImageSectionHeader.PointerToRawData);

		uint8_t* SectionBuffer = new uint8_t[SectionSize];

		PH_VIRTUAL_MEMORY_INPUT data{ m_Process, pSectionData, SectionBuffer, SectionSize, nullptr };
		NTSTATUS status = RWPM( &data, IO_CODES::I_ReadVirtual );
		if (status != STATUS_SUCCESS)
		{
			printf( "failed to read section buffer\n" );
			return NULL;
		}

		for (int i = 0; i < SectionSize; i++)
		{
			if (SectionBuffer[i] == 0x0)
			{
				DWORD_PTR dwOffset = 0;
				while (SectionBuffer[dwOffset + i] == 0)
				{
					if ((i + dwOffset) >= SectionSize)
						break;

					dwOffset++;
				}

				if (dwOffset >= cave_size)
				{
					if (ImageSectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE 
						&& ImageSectionHeader.Characteristics & IMAGE_SCN_MEM_READ 
						&& strcmp( (LPSTR)ImageSectionHeader.Name, ".text" ) == 0)
					{
						delete[] SectionBuffer;
						return (uintptr_t)(ImageSectionHeader.PointerToRawData + i);
					}
				}

				i += (int)dwOffset;
			}
		}

		if (i == NTHeader.FileHeader.NumberOfSections - 1)
			delete[] SectionBuffer;

		pImageSectionHeader++;
	}
	return NULL;
}
