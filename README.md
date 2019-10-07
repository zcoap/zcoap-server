# zcoap-server

A light weight, multi threaded, highly standards compient CoAP (RFC 7252) server designed for use with microcontrollers.

This project has been open-sourced by [Zepto Life Technology](http://zeptolife.com/) where it is used in production medical device firmware.

# Compile

This project uses CMAKE!  Yay cross-platform for the win!

## Linux
 
 On Ubuntu 19, for example:

 ```
 $ sudo apt install cmake
 $ sudo apt install build-essential
 $ cmake CMakeLists.txt
```
At this point you will have a working compiler and a working Makefile.

Now run make:

```
$ make
```

And you will end up with binaries in 

## Win32 Visual Studio 2019

Building and running the example in Visual Studio is just as easy.

First, you will need to have Linux/C++ "workload" enabled for Visual Studio.  This is a check-box you were offered when installing Visual Studio.  It's easy to add this after the fact too here are instructions: https://docs.microsoft.com/en-us/cpp/linux/download-install-and-setup-the-linux-development-workload?view=vs-2019

Open Visual Studio but don't open a project.  On the bottom right of the splash screen there's a button that says "Continue Without Code."

Then choose File->Open->CMake... and select the CMakeLists file at the root of the source tree.

The output window will immediately begin running CMake which generates build files for Visual Studio under the zcoap-server/out folder.

# Run Examples

There are simpel example programs which can be run under Windows and Linux.

There is also an in-depth description on how one might integrate this simple library into a microcontroller design.

## Linux

The program examples/example-server-linux.c contains example code you can run under Linux.

## Win32 Visual Studio 2019

The program examples/example-server-win32.c contains example code you can run under Linux.

## Microcontroller integration

On a microcontroller...

# Configuration Switches

The file src/config.h has a number of well documented compile switches.

