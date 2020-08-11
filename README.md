This is a fork of https://github.com/seanmiddleditch/libtelnet
particularly motivated by this issue https://github.com/seanmiddleditch/libtelnet/issues/19

# LIBTELNET Multiconnection Proxy

The repository has largely been untouched and only the proxy C-File and cmake file for it have been modified.
The reason this is in a separate repo is that the Proxy is now multithreaded and uses the pthread C-library and compiling the proxy by itself gave me compilation errors. This unfortunately means that portability took a hit. The proxy has been written for Linux (it might work on Unix in general but I haven't tested it).

### Usage
Is pretty much the same as the original proxy, except that it will not stop until the user writes an 'x' + Enter to stdin.
TODO: implement shutdown by connecting through a port and shutdown by SIGTERM and shutdown by SIGINT, confirm that possibly lost memory blocks as reported by Valgrind are not dangerous

files that have been changed

+ `util/CMakeLists.txt`     added pthread library link flag
+ `util/telnet-proxy.c`     implemented the multiconnection proxy
+ see Original_README.md for more information
