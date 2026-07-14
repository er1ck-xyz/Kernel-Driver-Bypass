# Kernel Driver Bypass

Base project for anti-cheat bypass (EAC/BE) using kernel-mode (ring0) to user-mode (ring3) communication.

## Core Concepts & Features
- **Arbitrary Memory R/W:** Physical and virtual memory operations, bypassing standard user-mode memory protections (CR3 manipulation, attach process bypass).
- **Manual Mapping:** Support for manual loading of the driver (via vulnerable drivers like Intel/Capcom mapping) to bypass Driver Signature Enforcement (DSE).
- **Stealth Communication:** Undetected ring0-ring3 communication. Avoiding standard `DeviceIoControl` (IOCTLs). Options include shared memory, `.data` pointer swapping in legitimate drivers, or hook-based dispatching.
- **Thread & Handle Obfuscation:** Stripping handles and thread call stack spoofing to remain hidden from manual analysis and automated AC heartbeats.
- **DKOM (Direct Kernel Object Manipulation):** Modifying EPROCESS / KTHREAD structures to hide processes, elevate tokens, or remove callbacks (ObRegisterCallbacks).

## Project Structure
- `/Driver/`: C/C++ source code for the ring0 driver (WDM).
- `/Usermode/`: Ring3 application for interface and payload injection (reading/writing to the target process).
- `/Includes/`: Headers for undocumented Windows NT internal structures.

## Disclaimer
This codebase is developed purely for educational and security research purposes (Reverse Engineering).

## TODO
- [ ] Implement communication hook (e.g., function pointer swap in a signed driver).
- [ ] Add dynamic offset resolution to support multiple Windows builds.
- [ ] Implement physical memory translation (PTE/PDE manipulation).
