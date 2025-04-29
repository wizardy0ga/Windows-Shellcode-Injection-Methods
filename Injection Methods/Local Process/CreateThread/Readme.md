## Using CreateThread to execute shellcode

### What is CreateThread?

[CreateThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread) is a windows api call which starts a new thread of execution within the calling process. This API call can be used to launch a new thread which begins executing code at the base address of some shellcode.

```c
HANDLE CreateThread(
  [in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
  [in]            SIZE_T                  dwStackSize,
  [in]            LPTHREAD_START_ROUTINE  lpStartAddress,
  [in, optional]  __drv_aliasesMem LPVOID lpParameter,
  [in]            DWORD                   dwCreationFlags,
  [out, optional] LPDWORD                 lpThreadId
);
```

The most important parameter related to this API call is **lpStartAddress**. This parameter provides the shellcodes location in memory where the it will begin reading and executing the instructions. No other parameters are necessary to execute the shellcode.