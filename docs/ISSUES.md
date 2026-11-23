
## Bugs and Issues:

This document describes issues and limitations of the tool. There is no guarantee these will be addressed.

### Known Issues:

* Limited Instruction Sets - Internal IR has a limited instruction set, some instructions are not supported
* There are some hard-coded values that may break the tool on other systems - ie. radare2 commands and command prompt and password in guest
* Hy2 produces duplicate results
* Incomplete documentation - there are too many config options and weird quirks, more documentation is needed
* Type Errors - in our implementation of cast instructions, some cast operations are not implemented correctly, our internal IR removes cast operations
* Handling different Languages - for languages such as go and rust, standard libraries end up being included in the analysis as they are in the same page as the actual binary making it very exprensive. This could easily be fixed.
* Symbol Resolution - hy2 relies on function names, if it is unable to match basic blocks to function names it may result in false negatives.

### Won't Fix

- panda-re - is not supported on newer versions of Linux. The alternative would be to write an extension for QEMU that does all the same tracing.
- Feasibility analysis - Doesn't reason about calls to external functions (ie. calls to strlen() made by the program), and struggles with complex relationships between variables. 

### Potential Future Improvements:

* Improving displaying of results
* Feedback for errors
* Instructions for configuration and during workflow
* Introduce an interface for introducing static info.
* Using static extension to execute program with arbitrary values 

### To Dos:

* Improving general ease of use
 
