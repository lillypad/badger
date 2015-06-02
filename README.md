# badger
The swiss army knife for windows exploit development.
---ABOUT---
Version: 1.0a
Made By: Arc Network Security
Website: www.arcnetworksecurity.com
This application is designed to be the Swiss Army Knife of windows exploit development
Allowing exploit developers to think more about development than the repetitive tasks done everyday
To participate in this project email lilly@arcnetworksecurity.com
---FEATURES TO COME---
- SEH Detection and Enumeration
- Mangled RVA Table Fix (some PE files don't have correct RVA Table Offset Flag i.e. user32.dll)
- Alpha-Numberic Shellcode Reference
- Suggestions are welcome

Examples:
badger --aslr-check
badger --lib library.dll function
badger --enable-dep or --disable-dep
badger --enum library.dll
badger --about
Descriptions:
--aslr-check: Shows RSP and ESP to aid in discovering ASLR best run several times, if values change ASLR is enabled.
--lib: Shows the function actual address when loaded into memory ASLR may change this if enabled
--enable-dep and --disable--dep: Requires administrator command prompt and will allow to enable/disable DEP for troubleshooting.
--enum: This will give library headers and information including functions and actual addresses
--about: The about screen
