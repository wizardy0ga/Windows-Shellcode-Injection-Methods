# Threadless shellcode execution via Fibers

[Fibers](https://learn.microsoft.com/en-us/windows/win32/procthread/fibers) are a scheduled unit of execution similar to threads, except they live entirely within userland. Per microsoft, *operations performed by a fiber are considered to have been performed by the thread that runs it*. All fiber execution events must be scheduled by the calling application, there is not involvement of an OS scheduler.

> [!IMPORTANT]
> Since fibers live in userland, security solutions running at the kernel level will not have any visbility into what the fiber is doing since the fiber never touches the kernel. This differs from threads in that threads operate from the kernel & are therefore visible to kernel based security solutions.

To execute shellcode in a fiber, we must follow these steps:

1. Convert the current working thread to the *primary fiber*. This is done with [ConvertThreadToFiber](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-convertthreadtofiber). Since fibers can only execute from other fibers, the main thread needs to be converted.

2. Create the fiber using [CreateFiber](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfiber). This function takes the base address of the shellcode to execute & returns the address of the fiber.

3. Schedule the fiber to execute with [SwitchToFiber](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-switchtofiber). Fibers are executed by switching to it from another fiber. 

Optionally to cleanup, we need to convert the primary fiber back to a main thread & discard the fiber. This is done with [ConvertFiberToThread](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-convertfibertothread) and delete the fiber we created with [DeleteFiber](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-deletefiber).

# Further Reading

https://learn.microsoft.com/en-us/windows/win32/procthread/fibers  

https://learn.microsoft.com/en-us/windows/win32/procthread/using-fibers  

https://www.bordergate.co.uk/shellcode-execution-via-fibers/  

https://www.linkedin.com/pulse/convertthreadtofiber-patching-dana-behling-4vbrc  

