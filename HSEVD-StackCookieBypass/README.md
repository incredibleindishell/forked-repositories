```
    __  __           __   _____           
   / / / /___ ______/ /__/ ___/__  _______
  / /_/ / __ `/ ___/ //_/\__ \/ / / / ___/
 / __  / /_/ / /__/ ,<  ___/ / /_/ (__  ) 
/_/ /_/\__,_/\___/_/|_|/____/\__, /____/  
                            /____/        
			Extreme Vulnerable Driver
							Exploits
```

### HackSys Extreme Vulnerable Driver - StackOverflow Exploit with StackCookie Bypass

StackOverflow exploit, which exploits a vulnerable function within the HEVD Kernel driver and bypasses the Stack Cookie protection (/GS).

# How does this exploit work:

* First allocate a RWX memory page in which we host our Shellcode.
* Copy our Token Stealing Shellcode (including the recovery opcodes) into the executable memory page.
* Get a Handle to the HacksysExtremeVulnerableDriver device.
* The memcpy (RtlCopyMemory) within the vulnerable function doesn't do any bounds checking, so we can corrupt the stackframe.
* This function is compiled with Stack Cookie protection (/GS), so we can't overwrite the return address without getting a BSOD from kernelmode.
* To bypass the Stack Cookie we need to overwrite the Structured Exception Handler address within the stack frame and trigger an exception in the kernel so the SEH executes our payload.    
* To do this, we're going to create a File Mapping Object and map this into the address space of the exploit process.
* We need to put our userbuffer at the end of the File mapping Object and fill it with the address (pointer) to our Payload until the address of the SEH has been overwritten.
* Use the DeviceIoControl() function with the IOCTL code of our device/function to send the Userbuffer to the driver in Kernelspace and send 4 extra bytes which falls outside our File Mapping Object/UserBuffer.
* These extra 4 bytes will cause an exception in the kernel during the memcopy of the userbuffer into the kernelbuffer, because the 4 bytes are within unallocted memory and will cause an Access Violation.
* The Access Violation will trigger the Structured Exception Handler which we have overwritten with the address of our payload, so EIP jumps into our Shellcode. 
* Our Shellcode replaces the token handle of the exploit process with the token handle of PID 4 (System), creates a new cmd.exe process using this System Token and recovers the Stackframe.  

Runs on:

```
This exploits only works on Windows 7 x86 SP1 (Version 6.1.7601).
``` 

Compile Exploit:

```
This project is written in C and can be compiled within Visual Studio.
```

Load Vulnerable Driver:

```
The HEVD driver can be downloaded from the HackSys Team Github page and loaded with the OSR Driver loader utility.
```
