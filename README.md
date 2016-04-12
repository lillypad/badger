# badger
The swiss army knife for windows exploit development.<br/>
---ABOUT---
Version: 3.0<br/>
Made By: Lilly Chalupowski<br/>
This application is designed to be the Swiss Army Knife of Windows exploit development<br/>
Allowing exploit developers to think more about development than the repetitive tasks done everyday<br/>
To participate in this project email lilly@arcnetworksecurity.com<br/>
IMPORTANT: By using this application you indemnify and hold harmless Arc Network Security\nfor any unethical application or misuse of this software<br/>
---WHAT'S NEW---
- Now Using Structs for Easy to Read Code
- Includes ASLR Bruter
- Major code clean up and overhaul from alpha version<br/>
---FEATURES TO COME---
- ROP Gadget Dumps
- x64 Support
- x64 AlphaNumeric Shellcode Reference
- Suggestions are welcome

Examples:
- badger --aslr-check
- badger --lib library.dll function
- badger --enable-dep or --disable-dep
- badger --enum library.dll
- badger --about
Descriptions:
- --aslr-check: Shows RSP and ESP to aid in discovering ASLR best run several times, if values change ASLR is enabled.
- --lib: Shows the function actual address when loaded into memory ASLR may change this if enabled
- --enable-dep and --disable--dep: Requires administrator command prompt and will allow to enable/disable DEP for troubleshooting.
- --enum: This will give library headers and information including functions and actual addresses
- --about: The about screen
