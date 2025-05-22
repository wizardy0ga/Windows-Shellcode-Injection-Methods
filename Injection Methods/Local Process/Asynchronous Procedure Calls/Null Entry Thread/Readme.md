## Asynchronous Procedure Call (APC) Injection via CreateThread

This variant doesn't rely on alertable / suspended threads. While tinkering with APC injection, i noticed that a thread can be created with a null entry point & still execute an APC. Therefore, I've included the code in this repository. This goes against the standard requirements (that i'm aware of) for APC injection which is why it's interesting. Further research is required here.

### Analysis

The injector is executed on the victim machine. A thread & the asynchronous procedure call is queued to the thread.

<p align=center>
    <img src=data/execute.png></img>
    <h6 align=center>Figure 1: Executing the APC injector</h6>
</p>

After waiting 5-10 seconds for the procedure to be executed, a shell is caught on the attackers machine. For demonstration purposes, an exit command is issued.

<p align=center>
    <img src=data/attacker.png></img>
    <h6 align=center>Figure 2: Catching the shell on the attackers machine & exiting</h6>
</p>

The injected thread & process cleanly exit.

<p align=center>
    <img src=data/complete.png></img>
    <h6 align=center>Figure 3: Cleanly exiting the APC injector process</h6>
</p>