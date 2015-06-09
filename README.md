# badger
The swiss army knife for windows exploit development.<br/>
---ABOUT---
- Version: 2.0
- Made By: Arc Network Security
- Website: www.arcnetworksecurity.com
- This application is designed to be the Swiss Army Knife of windows exploit development
- Allowing exploit developers to think more about development than the repetitive tasks done everyday
- To participate in this project email lilly@arcnetworksecurity.com <br/>
---WHAT's NEW--
- Alpha-numeric shellcode reference chart
- RVA Table Bug Fixed
- Supports more than one command at a time
- Major code overhaul and cleanup from alpha
- Optional to list all functions with --list functionality
---FEATURES TO COME---
- SEH Detection and Enumeration
- ASLR dll entropy test
- Security Cookie or Canary Enumeration
- Suggestions are welcome

Examples:
- badger --aslr-check
- badger --lib library.dll function
- badger --enable-dep or --disable-dep
- badger --enum library.dll
- badger --enum library.dll --list
- badger --about
- badger --alphanum-ref
Descriptions:
- --aslr-check: Shows RSP and ESP to aid in discovering ASLR best run several times, if values change ASLR is enabled.
- --lib: Shows the function actual address when loaded into memory ASLR may change this if enabled
- --enable-dep and --disable--dep: Requires administrator command prompt and will allow to enable/disable DEP for troubleshooting.
- --enum: This will give library headers and information including functions and actual addresses
- --about: The about screen
