## Hijacking an existing thread
The developer can enumerate potential threads that already exist on the host & search for a thread in the local process. This offers opsec at the cost of payload stability. The payload will also take some time to execute as Windows will need to schedule the threads execution after it's resumed.

### The THREADENTRY32 Structure
The [THREADENTRY32](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-threadentry32) structure represents a thread entry in a list of threads returned in a snapshot. The structure contains information about the thread such as the thread id & associated process id. This information in particular is relevant to thread hijacking as we'll need to ensure the thread is in this process and isn't the main thread. Hijacking the main thread would result in the loader crashing.

### Core API Calls

#### [CreateToolhelp32Snapshot](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)

```c
HANDLE CreateToolhelp32Snapshot(
  [in] DWORD dwFlags,
  [in] DWORD th32ProcessID
);
```

CreateToolhelp32Snapshot will create a snapshot of all running threads on the system. The **TH32CS_SNAPTHREAD**

#### [Thread32First](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32first)
```c
BOOL Thread32First(
  [in]      HANDLE          hSnapshot,
  [in, out] LPTHREADENTRY32 lpte
);
```

This function enumerates the first thread in the snapshot. All subsequent threads are enumerated by **Thread32Next**.

#### [Thread32Next](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32next)

```c
BOOL Thread32Next(
  [in]  HANDLE          hSnapshot,
  [out] LPTHREADENTRY32 lpte
);
```

Thread32Next enumerates all subsequent threads in a snapshot after the initial call to **Thread32First**. 

#### [OpenThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread)
```c
HANDLE OpenThread(
  [in] DWORD dwDesiredAccess,
  [in] BOOL  bInheritHandle,
  [in] DWORD dwThreadId
);
```

OpenThread will acquire a handle to the target thread. For thread hijacking, the handle will need the **THREAD_GET_CONTEXT**, **THREAD_SET_CONTEXT**, **THREAD_SUSPEND_RESUME** & **SYNCHRONIZE** access rights. See [Thread Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/procthread/thread-security-and-access-rights) for further information on access rights.

| Access Right | Purpose |
| - | - |
| THREAD_GET_CONTEXT | Get the context of a thread
| THREAD_SET_CONTEXT | Set the context of a thread
| THREAD_SUSPEND_RESUME | Suspend and resume the thread
| SYNCHRONIZE | Allow the thread handle to be passed to wait functions such as **WaitForSingleObject**.

#### [SuspendThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-suspendthread)
```c
DWORD SuspendThread(
  [in] HANDLE hThread
);
```

Suspends the thread prior to manipulating the context.


#### [ResumeThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread)

```c
DWORD ResumeThread(
  [in] HANDLE hThread
);
```

ResumeThread will instruct the thread to lift the suspension and resume execution which executes the shellcode.

### Debugging

The thread hijacker is launched & locates a thread under the id **22484**. The threads RIP register is set to the address of the shellcode at **0x00007FF7BCEC1000**.

<p align=center>
	<img src=data/debug.png></img>
  <h6 align=center>Figure 1: Executing the thread hijacking program</h6>
</p>

Looking at the call stack, the thread was executing the function **ntdll!TppWorkerThread** prior to hijacking indicating this is a worker thread from a pool.

<p align=center>
	<img src=data/callstack.png></img>
  <h6 align=center>Figure 2: Callstack of the hijacked thread</h6>
</p>