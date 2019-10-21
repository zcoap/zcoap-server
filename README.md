# zcoap-server

A very light weight, highly standards complient CoAP (RFC 7252) server designed for use with microcontrollers.  This library is designed to be very easy to use, without any assumptions about treading, crypto support, how you receive/send the data (TCP/UDP, Serial).  You define a CoAP tree and pass the zcoap-server a CoAP frame and it produces CoAP frame responses. 

This project has been open-sourced by [Zepto Life Technology](http://zeptolife.com/) where it is used in production medical device firmware.

# Compile

This project uses CMAKE!  Yay cross-platform for the win!  Or you can easily include the content of /src in your microcontroller design and be off to the races!

The CMakeLists.txt file defines 3 targets:

1. zcoap-server - a lib which contains all of the logic for parsing CoAP frames and sending responses.
2. example-server-linux - an example program which can be run under Linux.  The program listens on a UDP socket for incomming messages.  When a UDP frame comes in, the bytes of the payload are presumed to be a CoAP frame and they are handed to the zcoap-server->coap_rx function.
3. example-server-win32 - an example program which can be run under Windows from Visual Studio 2019.

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

And you will end up with binaries in folders dependant on your environmetn - look for an "out" directory.

## Win32  and Visual Studio 2019

Building and running the example for Windows is just as easy.  Let's assume you're using Visual Studio 2019.

First, you will need to have Linux/C++ "workload" enabled for Visual Studio.  This is a check-box you were offered when installing Visual Studio.  It's easy to add this after the fact too, here are instructions: https://docs.microsoft.com/en-us/cpp/linux/download-install-and-setup-the-linux-development-workload?view=vs-2019

Holy cow, it's so easy though!

Open Visual Studio but don't open a project.  On the bottom right of the splash screen there's a button that says "Continue Without Code."

Then choose File->Open->CMake... and select the CMakeLists.txt file at the root of this source tree.

The output window in Visual Studio will immediately begin running CMake which generates build files for Visual Studio under the zcoap-server/out folder.

# Run Examples

There are simple example programs which can be run under Windows and Linux.

There is also an in-depth description on how one might integrate this library into a microcontroller design - that's on its way...

The example CoAP tree looks similar to this on both examples:

/.well-known/core
/telemetry/temperature/
/telemetry/temperature/max
/telemetry/digits
/telemetry/name

The Linux example gives shows how to dynamically create nodes based on the content of the /tmp directory on your Linux machine, using the .gen pointer.

## Linux

The program example-linux/server-linux.c contains example code you can run under Linux.

## Win32 Visual Studio 2019

The program example-win32/server-win32.c contains example code you can run under Linux.

## Microcontroller integration

On a microcontroller... until the example is added, all you need to do is include:

* zcoap-server.c
* zcoap-server.h
* zsnprintf.c
* zsnprintf.h
* config.h

And finally, you need to provide a "platform.h" as show in the examples to define information about your environment. 

Then in your microcontroller code, when you receive a CoAP frame hand it to the library along with the root tree, in the function coap_rx, as show in the example dispatch function:

```C
static void dispatch(const SOCKET *receive_sock, const size_t len, const uint8_t payload[])
{
    // Make a request
    coap_req_data_t req = {
        // This is the socket file descriptor, but it's not needed in this win32 example
		// Instead, we will pass through a pointer to the ClientSocket which we will send a response on
        .context = 0,
        // The address we should respond to
        .route = receive_sock,
        // Bytes of the cCoAP payload, including the UDP frame
        .msg = (const coap_msg_t *)payload,
        // Number of bytes in the payload
        .len = len,
        // Hold function to call to respond to the message
        .responder = &coap_udp_respond,
    };

    // Submit the request with the reference to the root of the tree built above
    coap_rx(&req, &root);
}
```

# Design Notes

* The server is intended to be highly standards complient to [RFC7252](https://tools.ietf.org/html/rfc7252).  Please file issues if you find comliance problems and we will fix them!
* The server is entirly stateless, as the RFC seems to intend.
* In general, you statically define your tree but it is possible to dynamically modify the tree at runtime.
* It allows you to define your own malloc, see ZCOAP_MALLOC.
* Malloc is only needed with a few response types.
* Supports C89 if needed, for all the old-school compilers out there (including MSVC...).
* The library can be easily used with UART channels.  Simply change how the dispatch() and coap_udp_respond() methods work in the examples.
* The library makes no assumptions on crypto support for your microcontroller, as the RFC intends, this means there is no TLS/DTLS support built in.
* The library does not assume you have threading (such as pthread), the thread you call coap_rx() on is the thread which generates and calls the resposne.  You can define your own ZCOAP_LOCK and ZCOAP_UNLOCK to make the code work in multi-threaded enviroments.  But this is only needed when you are using the built-in response fucntions such as, for example coap_get_int.  When you define your own GET/PUT functions you need to keep threading in mind and lock resources as needed.
* The library provides format extensions which we will be trying to make a formal part of the specification as more reserved Content-Formats registry types (section 12.3) are decided on.  In much the same way that CBOR [RFC7049](https://tools.ietf.org/html/rfc7049) might one day be a standard content type, we believe there should be wire formats for standardized types like "int32" or "double."  To this end, feel free to use binary wire types found in ZCOAP_EXTENSIONS.  There is a way to disable our custom types by defining SUPPRESS_ZCOAP_EXTENSIONS in platform.h.
* The library does not allow a client to observe resources per [RFC7641](https://tools.ietf.org/html/rfc7641).  Hopfully progress on this will be made in the future.

# Configuration Switches

In an effort to keep things really simple, there are not many compile switches supported by the library.  

The file src/config.h has a few of well documented compile switches.  You are expected to provide a platform.h file which overrides the defaults in config.h.  See the platform.h file found in the examples.

