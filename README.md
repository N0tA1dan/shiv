# SHIV

A toolkit made for hooking functions at a low level. 

## Goal

The goal of shiv is to be able to pass a functions address and some code to replace the function, and shiv will do the rest for you

Allow for user written code to be injected into a function

gain access to proc -> make proc write new memory -> write our payload memory -> overwrite target function with JMP instruction
