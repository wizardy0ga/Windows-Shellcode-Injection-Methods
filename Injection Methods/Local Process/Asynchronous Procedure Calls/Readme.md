## User-mode Asynchronous Procedure Call (APC) Injection

### What is an APC?

Asynchronous Procedure Calls are a windows feature which provides programmers the ability to execute code in a thread that's in an **alertable** state. When a thread enters an alertable state, it means it's awaiting the completion of another procedure, hence the asynchronous execution. During this wait time, it will begin executing procedures from the **APC Queue**.

This feature can be abused to execute shellcode by scheduling an APC in a target thread which is pointed at the shellcode.

To enter an alertable state, a thread must execute one of the following API calls:

- SleepEx
- SignalObjectAndWait
- MsgWaitForMultipleObjectsEx
- WaitForMultipleObjectsEx
- WaitForSingleObjectEx 

### Core API Calls

[QueueUserAPC](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)
```
DWORD QueueUserAPC(
  [in] PAPCFUNC  pfnAPC,
  [in] HANDLE    hThread,
  [in] ULONG_PTR dwData
);
```

QueueUserAPC schedules the APC function in the target thread by adding it to the threads APC Queue. The function address is specified by **pfnAPC** and the target thread is specifed via **hThread**.