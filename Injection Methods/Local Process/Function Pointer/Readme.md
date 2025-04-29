## Executing shellcode via Function Pointers

### What is a Function Pointer?
In C, a function pointer is a variable which holds the address of a function. The variables value is set to the address of a function which can be invoked through the variable.

> [!NOTE]
> The definition of the function pointer must have the same return type & parameters as the target function

### Example

```c

# include <stdio.h>

int add(int a, int b) {
	return a + b;
}

int divide(int a, int b) {
	return a / b;
}

int main() {
	int a = 10, b = 15, c = 0;

	// Declare a function pointer
	int (*function_pointer)(int a, int b);

	function_pointer = add;						// Assign the 'add' function address to the pointer

	c = function_pointer(a, b);					// Execute the function by calling the function pointer
	printf("%i + %i is %i.\n", a, b, c);

	function_pointer = divide;

	b = function_pointer(c, 5);
	printf("%i divided by 5 is %i.\n", c, b);

	return 0;
}

```

### Disassembly

This is the disassembly of the main function from [main.c](main.c).

The load effective address (lea) instruction sets the value of **rax** to the base address of the shellcode. The call instruction will execute the shellcode.

<p align=center>
	<img src=data/disassembly.png></img>
</p>

###### Figure 1: Disassembly of main() in [main.c](main.c)

### Debugging 

The shellcode has been stored at the address **0x7FF74B271000** which is the beginning of the .text section.

<p align=center>
	<img src=data/memory_map.png></img>
</p>

###### Figure 2: Memory map highlighting the .text section base address

**rax** is set to the base address of the shellcode, **0x7FF74B271000**. The call instruction will execute the shellcode by setting **rip** to **0x7FF74B271000** where execution will continue.

Since this is metasploit shellcode, it can be verified by the first 6 bytes which is a signature in shellcode generated from [msfvenom](https://www.offsec.com/metasploit-unleashed/msfvenom/).

<p align=center>
	<img src=data/debugger.png></img>
</p>

###### Figure 3: Breaking execution after **rax** is assigned the address of the shellcode