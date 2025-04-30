## Thread Hijacking

A 'thread' is a unit of code execution in a process. Each thread in a process contains it's own set of registers and other resources related to code execution. Thread hijacking is the process of taking control over a thread and manipulating the instruction pointer (RIP / EIP) to execute the shellcode. There are two methods of targeting a thread for hijacking, thread creation & enumeration. After a thread has been acquired, execution of the shellcode is the same.

### The CONTEXT Structure
A [CONTEXT](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context) structure represents the registers and other data associated with a thread of execution. This structure is required for manipulating the thread.

> [!IMPORTANT]
> The **ContextFlags** member of the CONTEXT structure must be set to **CONTEXT_CONTROL** prior to usage. **CONTEXT_ALL** can also be used.

### Core API Calls

#### [GetThreadContext](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext)

```c
BOOL GetThreadContext(
  [in]      HANDLE    hThread,
  [in, out] LPCONTEXT lpContext
);
```

GetThreadContext populates the CONTEXT structure with information about the thread.

#### [SetThreadContext](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext)

```c
BOOL SetThreadContext(
  [in] HANDLE        hThread,
  [in] const CONTEXT *lpContext
);
```

SetThreadContext applys the information in a CONTEXT structure to a thread.

### Putting it Together

Assume we have a handle to a suspended thread. We can populate the CONTEXT structure using **GetThreadContext**. From there, we'll set the **Rip** member of the structure to the base address of our shellcode in memory. Then, we'll use **SetThreadContext** to apply the CONTEXT structure to the thread which sets the threads rip register to the base of our shellcode. When the thread resumes, the shellcode is executed.

```c
CONTEXT Context = { .ContextFlags = CONTEXT_CONTROL }  // Initialize the CONTEXT structure & set the ContextFlags member to CONTEXT_CONTROL

GetThreadContext(hThread, &Context);                   // Populate the structure with information about the thread

Context.Rip = shellcode;                               // Set the instruction pointer to the base address of the shellcode

SetThreadContext(hThread, &Context);                   // Apply the new register information to the thread
```