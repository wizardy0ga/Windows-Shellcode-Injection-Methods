## Remote Process Shellcode Execution

Executing shellcode in a remote process refers to the practice of executing arbitrary code in the address space of another process.

This is an evasive measure which attempts to blend the activity of the shellcode in with another process. An example of a common injection target is internet browsers since the network traffic can blend in better with benign network activity.

## Handling Memory Permissions

In the [Local Process](../Local%20Process/Readme.md) section, all of the shellcode was allocated in the text section. This enables the shellcode to execute without requiring further api calls as the shellcode already sits in a location with the permissions required for execution.

When injecting into a remote process, we aren't afforded this luxury. We'll have to write out the code for allocating / writing the shellcode to the remote memory & handling the permissions assigned to the block of memory. The available memory protections in windows are described [here](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants#constants).

### Memory Permissions of Interest
| Permission | Description |
| - | - |
| PAGE_READWRITE | Allows the memory to be read or written to. Typically used when writing shellcode to the remote memory.
| PAGE_EXECUTE_READ | Allows the data held in the memory block to be executed. Used when executing the shellcode.
| PAGE_EXECUTE_READWRITE | Allows the memory block to be read from, written to & executed. This permission will set of alarms in EDR tools & is generally not considered opsec friendly.

### Core API Calls

#### [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
```
HANDLE OpenProcess(
  [in] DWORD dwDesiredAccess,
  [in] BOOL  bInheritHandle,
  [in] DWORD dwProcessId
);
```

Used to acquire a handle to the target process. The handle acts as a reference to the process in other API calls which modify the process. The **dwDesiredAccess** parameter specifies the access rights to open the handle with. At a minimum, you will need to specifiy **PROCESS_VM_OPERATION**, **PROCESS_VM_READ** & **PROCESS_VM_WRITE**. Further reading about access rights can be found [here](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights).

> [!CRITICAL]
> Specifying **PROCESS_ALL_ACCESS** can be a flag for some EDR's. It's best to call the handle with the minimum rights required for injection.

#### [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
```c
LPVOID VirtualAllocEx(
  [in]           HANDLE hProcess,
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType,
  [in]           DWORD  flProtect
);
```

Used for allocating memory in the target process. This memory will hold the shellcode. The **flAllocationType** parameter will specify the initial permissions for the memory block. Using **PAGE_READWRITE** will allow the shellcode to be written to the memory block.

> [!CRITICAL]
> Specifying **PAGE_EXECUTE_READWRITE** for the memory protection will be a flag for EDR's. It's safer to use the minimum required permissions & change permissions with **VirtualProtectEx** as necessary.

#### [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
```c
BOOL WriteProcessMemory(
  [in]  HANDLE  hProcess,
  [in]  LPVOID  lpBaseAddress,
  [in]  LPCVOID lpBuffer,
  [in]  SIZE_T  nSize,
  [out] SIZE_T  *lpNumberOfBytesWritten
);
```
Used for writing the shellcode from the host process to the target process in the buffer created with **VirtualAllocEx**.

#### [VirtualProtectEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
```c
BOOL VirtualProtectEx(
  [in]  HANDLE hProcess,
  [in]  LPVOID lpAddress,
  [in]  SIZE_T dwSize,
  [in]  DWORD  flNewProtect,
  [out] PDWORD lpflOldProtect
);
```

Used to change the permissions on the memory that's allocated for the shellcode. Typically, you'll start with **PAGE_READWRITE** to write the shellcode to the memory & then use this function to set the memory permissions to **PAGE_EXECUTE_READ**, allowing the shellcode to execute.