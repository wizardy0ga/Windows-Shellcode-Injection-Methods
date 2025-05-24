## APC Injection via Alertable Thread

This is the standard method of APC injection. This method requires a target thread to be in an alertable state. Once the thread reaches an alertable state, it will execute our shellcode which from the APC queue which was scheduled by the injector.

### Analysis

The injector is executed on the victim machine. A thread is created with the id **7124** which starts at the **Alertable** function & an APC pointing at the shellcode is queued to the thread. 

When the alertable function executes, the thread goes into the alertable state where it begins executing procedures from the APC queue. This executes the shellcode.

<p align=center>
    <img src=data/execution.png></img>
    <h6 align=center>Figure 1: Executing the injector & inspecting the thread</h6>
</p>

On the attacker machine, a shell is caught.

<p align=center>
    <img src=data/shell.png></img>
    <h6 align=center>Figure 2: Receiving the shell</h6>
</p>

For demonstration purposes, we'll use the [sysmon event parser](https://github.com/wizardy0ga/sysmon-event-parser) to analyze the events logged by sysmon.

No events were logged related to the creation of the local thread or scheduling of the APC as sysmon doesn't have these capabilities. Sysmon does log interesting events related to the cmd.exe execution & following network connections. In a real-world scenario, this information could still be used to detect suspicious activity.

<p align=center>
    <img src=data/sysmon.png></img>
    <h6 align=center>Figure 3: Reviewing the events logged by sysmon</h6>
</p>