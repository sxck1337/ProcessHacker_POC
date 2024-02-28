#pragma once

#include <Windows.h>
#include <string>
#include <strsafe.h>

class Helpers
{
public:
	static inline std::wstring wString( std::string input )
	{
		std::wstring output; 
		output.assign( input.begin( ), input.end( ) );
		return output;
	}

	static inline std::string String( std::wstring input )
	{
		std::string output; 
		output.assign( input.begin( ), input.end( ) ); 
		return output;
	}
	
	static inline bool SetPrivilege( const LPCSTR lpszPrivilege, const BOOL bEnablePrivilege ) 
	{
		TOKEN_PRIVILEGES priv = { 0,0,0,0 };
		HANDLE hToken = nullptr;
		LUID luid = { 0,0 };

		if (!OpenProcessToken( GetCurrentProcess( ), TOKEN_ADJUST_PRIVILEGES, &hToken )) {
			if (hToken)
				CloseHandle( hToken );
			return false;
		}

		if (!LookupPrivilegeValueA( nullptr, lpszPrivilege, &luid )) {
			if (hToken)
				CloseHandle( hToken );
			return false;
		}

		priv.PrivilegeCount = 1;
		priv.Privileges[0].Luid = luid;
		priv.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;

		if (!AdjustTokenPrivileges( hToken, false, &priv, 0, nullptr, nullptr )) {
			if (hToken)
				CloseHandle( hToken );
			return false;
		}

		if (hToken)
			CloseHandle( hToken );
		return true;
	}
};