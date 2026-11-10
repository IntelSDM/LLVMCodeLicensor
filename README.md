# Code Licensor
Built for LLVM 19.1 - Windows x64 <br> <br>

In recent years licensing agents such as denuvo have fallen on their head, with global hypervisor derived attacks, and as of very recently with massive full game reverse engineering projects becoming popular due to AI automated reverse engineering.<br>
This project DIRECTLY makes these forms of attack much more difficult. Keep in mind this isn't a final solution, you NEED to work MBA into areas and integrity checks. This shows you how to do proper licensing to modern standards. <br>
To bring it up to standards quickly, a lot of the none resistant/ already standardised licensing is based off [Connor-Jay's research](https://connorjaydunn.github.io/blog/posts/denuvo-analysis/).

## How Licensing Is Attacked
Licensing software such as denuvo used to be extremely effective as they used CPUID instructions for most of their HWID binding, this was amazing as you had 1 of 2 options:

* Use a hypervisor, Spoof CPUID on VMExit only when faulted from the game (preventing system breaking).
* Patch every check out of the game.

Hypervisors used to be very much a research level thing, either devved by full blown dev teams or by talented researchers primarily using them for game cheating. The implementations of most research level hypervisors has been very poor up until the past few years. <br>
Now hypervisors are so heavily documented, there are so many lightweight POCs and AI is so heavily trained, they have become the go to. Just simply wait for the game to fault on a licensing check, spam EPT hooks everywhere and wait for faults, spoof them all to a legitimate copy. <br>
This means you can also just hook other HWIDs such as IOCTL driven disk HWIDs by simply EPT hooking and waiting for the right parameters and caller positions. Or just checking if it comes from denuvo's PE section. <br>

## How do we exactly solve these issues?
So everything can be hooked right? Well not EVERYTHING, You see identifiers such as disk IDs, and normal HWIDs are not used by the game, thats why they can globally hook them without polluting the game. <br>
### Method 1
Using existing game functionality that must be used in EVERY game, to create HWID fingerprints. <br>
GPUAdapter and DisplayAdapter. Every game uses a render output. Directx, OpenGL or even GDI. This contains their Monitor information, GPU name, Adapter information, Resolutions. <br>
Blindly hooking any of these and giving them false information will result in the game breaking, windows functionality for monitor detection and various other factors. <br>
This forces the attacker to have to find every real and every fake site's RVA, and hook/patch only that one. So this alone wipes out automation attacks. <br>
### Method 2
Gadgets. [We use gadgets on Read/Write/Calls](https://github.com/IntelSDM/ROPFuscatorLLVM) to bind the actual codebase to the operating system. This means the build will only work for the exact operating system, as we indirectly use opcodes from known binaries for that users specific build <br>
This forces full program rewriting in order to delicense the binary for any other Windows build. <br>
[We then also do the same thing to all the imports](https://github.com/IntelSDM/ImportProtectionLLVM). Directly referencing the Windows build's imports, bypassing both IAT and EAT hooking. This means that identifying sites to strip for method 1 becomes hellish. <br>
It also binds the program to the windows build. <br>
Additionally, this is the part that AI can't stand, as we are flooding the context, our entire binary requires EVERY SINGLE IMPORT into its context, you can't unload it, you need to scan EVERYTHING. This means every time an AI agent comes into contact with our binary, it has to scan every gadget against any possible binary. <br>
Making AI attacks unfeasible.
### Method 3
Heuristics based HWID. Disk.cpp in the binary doesn't collect a HWID, It benchmarks the disk speeds. As long as you aren't using it in something with a lot of disk load, it will always give you a correct hash. <br>
The physical limits of the speed of your disk can't be spoofed, as it uses the common read/write file APIs. Hooking them out automatically is impossible. You need to attack the actual site. <br>
This is basically what Denuvo used to achieve with CPUID, a form of attack that you can't do anything but patch out, patching out kicks off the integrity checks, then you have to patch out ALL the integrity checks. <br>
<br><br>
This gives us an overall coverage of:
| TYPE | HWID | Attributes |
|---|---|---|
| **CPUID** | Basic CPU Information, Forces Hypervisor or Patch | Very fast and lightweight, nearly no overhead|
| **KUserSharedData** | Basic Memory/OS Information, Forces Hypervisor or Patch | Very fast and lightweight, nearly no overhead|
| **DisplayAdapter** | Display/GPU/Monitor, Prevents Automatic Patching/Hooks | Medium Overhead, takes maybe 120ms per cycle|
| **GPUAdapter** | Display/GPU/Monitor/PCID, Prevents Automatic Patching/Hooks | high Overhead, takes maybe 1s per cycle|
| **DiskID** | Disk Speed, Prevents Automatic Patching/Hooks | Extreme Overhead, takes maybe 3s per cycle|
| **Gadgets** | Binds The Entire Binary To The Windows Build's Code, Forces patching | No Overhead|



## How to use
* First of all you need a build server that already grabs the users dll info. DLLGrabberUtility.h Is how you grab the info from the user, Call GrabIdentity on their end. 
* Then once we have the TimeDateStamp SizeOfImage DllName from the user, we can query the DLLs directly from Microsoft's download server; as seen in OfficialDLLDownloader.h.
* So you now have the dlls from your user from Microsoft's server, they are on disk, you then use the DLLExportGrabber.h on them, use them in the pass.
* You also need the User's HWID sent over to you. Deploy the collection code on their client and run LicenseCollection.cpp -> CollectBuildTimeFingerprints().
* Send all the HWID to your build server 
* Each user has a unique build. 
* Cache the output so you aren't killing performance rebuilding your product each time the user loads.

## Annotations
```c
__attribute__((annotate("DiskID")))
``` 
* Benchmarks The Disk, Really Slow, use only where the disk isn't heavily being used (Or it could fail the benchmark).
```c
__attribute__((annotate("GPUAdapter")))
```
* Grabs Information From Render Pipeline. Use in areas where code can be slow.
```c
__attribute__((annotate("DisplayAdapter")))
```
* Grabs Information From Windows Display Information. Use in areas where code can be slow.

Everything else is applied automatically binary wide. It also automatically uses the stack negative trick to prevent VEH. <br> <br>
<img width="388" height="487" alt="image" src="https://github.com/user-attachments/assets/2a160a54-e1e9-4e92-9443-6631bb4f436a" /> <br>
<img width="511" height="796" alt="image" src="https://github.com/user-attachments/assets/dfd5cab1-5cfc-4994-b13e-fb1979c7a0be" /> <br> 
<img width="293" height="658" alt="image" src="https://github.com/user-attachments/assets/c535e175-011c-4b44-8c63-7dfb15cb9189" /> <br>


## How To Build
* Download [LLVM 19.1](https://github.com/llvm/llvm-project/releases/tag/llvmorg-19.1.0)
* Download [VCPKG](https://github.com/microsoft/vcpkg)
* VCPKG install asmjit
* Open build.bat in a text editor.
* Find the LLVM 19.1 references in the command line, Change them to your file path.
* Find the VCPKG references in the command line, Change them to your file path.
* Run the build script
* Build your application with the ``` -load-pass-plugin ``` Param to the FunctionPass.dll
