## Hijacking a newly spawned thread

At the cost of opsec, the developer can create a thread, offering more stability than hijacking a thread which already exists.

### Core API Calls

#### [CreateThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread)

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

CreateThread is used to create a new thread in a suspended state. To create the thead in a suspended state, the **CREATE_SUSPENDED** flag needs to be used in the **dwCreationFlags** parameter. All other flags can be set to 0 if one desires. The thread only needs to be created in a suspended state.

#### [ResumeThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread)

```c
DWORD ResumeThread(
  [in] HANDLE hThread
);
```

ResumeThread will instruct the thread to lift the suspension and resume execution which executes the shellcode. 

### Debugging

A suspended thread is created with the id **11384** and the threads register context is acquired. Rip is set to the base address of the shellcode **0x7FF656011000** and the new context is applied to the thread. When the thread resumes execution, the shellcode executes. 

> [!IMPORTANT]
> Notice that the **Entry** field of the thread is pointing to our shellcode.

<p align=center>
	<img src=data/debug.png></img>
  <h6 align=center>Figure 1: Inspecting the hijacked threads entry point</h6>
</p>

While tinkering with this code, i noticed that passing a null address to **lpStartAddress** in **CreateThread** can hide the entry point.

```c
hThread = CreateThread(0, 0, 0, 0, CREATE_SUSPENDED, &ThreadId)
```

When looking at the thread in a debugger and other tools capable of thread analysis, the entry point is listed as 0x00. This could be an indicator of it's own however the payloads address in memory was hidden. In the image below, our malicious thread was given the ID **7852** and the entry point was listed as **0x00**.


<p align=center>
	<img src=data/debug2.png></img>
  <h6 align=center>Figure 2: Inspecting the hijacked thread when spawned with NULL entry point</h6>
</p>

Since we have control over the threads initial entry point, a dummy function can be used to spoof the entry point which hides our shellcode & doesn't leave a potential IoC in the form of a null entry point. The **MessageBoxW** function was used as an example. The image below shows thread id **29824** with an entry point of **MessageBoxW** however it is actually executing the shellcode.

```c
hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MessageBoxA, 0, CREATE_SUSPENDED, &ThreadId)
```

<p align=center>
	<img src=data/debug3.png></img>
  <h6 align=center>Figure 3: Inspecting the hijacked thread when spawned with a spoofed entry point</h6>
</p>

Upon further inspection of the threads callstack, things begin to appear abnormal as the entry point is listed as MessageBoxW however the thread began executing in Creation.exe & calls **connect** from winsock while MessageBoxW isn't present in the call stack. We can hide the entry point however the curious analyst will detect this by inspecting the call stack.

<p align=center>
	<img src=data/callstack.png></img>
  <h6 align=center>Figure 4: Inspecting the callstack of the spoofed thread</h6>
</p>

The image below shows the call stack of a thread that was created & executed while pointing at MessageBoxW. Notice that the thread begins in **ntdll.dll!RtlUserThreadStart** and then moves to **kernel32.dll!BaseThreadInitThunk** before executing the MessageBoxA function. If you open a process analysis tool such as [process explorer](live.sysinternals.com/procexp64.exe) and begin inspecting threads on various processes, you'll notice nearly all of the threads have these functions at the bottom of their call stack where the thread began execution. This is the expected behaviour for a legitimate thread.

<p align=center>
	<img src=data/benign_callstack.png></img>
  <h6 align=center>Figure 5: Inspecting the callstack of a legitimate MessageBoxW thread</h6>
</p>