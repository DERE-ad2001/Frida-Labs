# Frida-Labs

![Frida-Labs](https://github.com/DERE-ad2001/Frida-labs/assets/67110398/e5794a19-1ee7-4820-81c7-fd362f78c842)

This repository contains a series of challenges designed for learning Frida for Android. These are not like hardcore Capture The Flag (CTF) applications but will help you to start with Frida and its commonly used APIs. If you are entirely new to Frida, this is the perfect repository to get started. I have organized the challenges in a way that covers everything from the basics to an intermediate level.

These challenges have flags but that's not the primary goal here. You can easily get the flags using other methods. But the goal of these challenges is to equip you with the fundamentals, helping you to use Frida and understand the Frida scripts written by others. While doing these challenges, try to obtain the flag through many ways as possible using frida. I will be updating this repository with new challenges whenever I find something interesting.

All the APKs are inside the directories, and the solutions are also provided in the solution directory. If you are not familiar with the setup and have like zero idea about Frida, you can go through the first solution.

If you find this series useful please share :)

Portuguese version: https://github.com/n3k00n3/Frida-Labs-PT

## Challenges Overview

- Challenge 0x1 : Frida setup, Hooking a method
- Challenge 0x2 : Calling a static method
- Challenge 0x3 : Changing the value of a variable
- Challenge 0x4 : Creating a class instance
- Challenge 0x5 : Invoking methods on an existing instance
- Challenge 0x6 : Invoking a method with an object argument
- Challenge 0x7 : Hooking the constructor
- Challenge 0x8 : Introduction to native hooking
- Challenge 0x9 : Changing the return value of a native function
- Challenge 0xA : Calling a native function
- Challenge 0xB : Patching instructions using X86Writer and ARM64Writer

## Recent Updates (November 2026)

### Frida 17+ API Migration
All solutions have been updated to use the **Frida 17+ JavaScript API** (released May 2025, current version 17.25.2). Key breaking changes addressed:

| Old API (Frida ≤16) | New API (Frida 17+) |
|---------------------|---------------------|
| `Module.getBaseAddress("lib.so")` | `Process.getModuleByName("lib.so").base` |
| `Module.findBaseAddress("lib.so")` | `Process.findModuleByName("lib.so")?.base` |
| `Module.findExportByName("lib.so", "func")` | `Process.getModuleByName("lib.so").findExportByName("func")` |
| `Module.getExportByName("lib.so", "func")` | `Process.getModuleByName("lib.so").getExportByName("func")` |
| `Module.enumerateExports("lib.so")` | `Process.getModuleByName("lib.so").enumerateExports()` |
| `Memory.readU32(ptr)` | `ptr.readU32()` |
| `Memory.writeU32(ptr, val)` | `ptr.writeU32(val)` |
| `Process.enumerateModules({onMatch, onComplete})` | `Process.enumerateModules()` (returns array) |

### New Patterns Introduced
- **Module Observation**: Use `Process.attachModuleObserver()` instead of polling/timers to wait for library loads
- **Code Patching**: Use `Memory.patchCode()` instead of `Memory.protect()` + `X86Writer`/`Arm64Writer` — handles memory protection automatically
- **NativePointer Methods**: Use instance methods like `args[0].readCString()` instead of static `Memory.readUtf8String(args[0])`
- **Java Bridge**: In some contexts, explicitly load with `const Java = require('frida-java-bridge')`

Each solution now includes both the classic approach (for learning) and the **Frida 17+ recommended approach** using modern APIs.

## Further Resources

- https://learnfrida.info/advanced_usage/
- https://codeshare.frida.re/
- https://frida.re/docs/javascript-api/ (Frida 17+ API reference)
- https://frida.re/news/2025/05/17/frida-17-0-0-released/ (Frida 17 release notes)
