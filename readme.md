## Project Platypus

![platypus_with_computer](./extra/imgs/platypus.jpg)

This will get flushed out more in the future, allowing for more complex flows to be tracked. Currently it find and decrypt strings from a known decryption function reference.


Please note: This is in the testing phase so options may be limited and you will have to change/modify the code to adapt to new options

### Intention

No AI code generation will be used to generate the underlying code (only caveat would be with helping generate tests for
the classes as I hate the tediousness at building out tests). Additionally, there **will not** be *any* AI/LLM/ML
\*shenanigans\* happening with decompiling, reversing, and rehydrating the code. 

Why no AI/LLM stuffs? → While it *kinda* does work, the results are not 100% reproducible, meaning that what you see and what I see 
may and likely do differ. These differences, whether large or small, may result in very 
different outcomes in how you evaluate each application, potentially resulting in skewed results.

As such, it is my belief and opinion that this tool should:
  - Allow for 100% reproducible results
  - Give you as near full control of your reversing environment as possible
    - (hopefully with as many batteries included as is feasible)
  - Allow for manual work, or automation

### Limitations

Running native code is experimentally supported and will likely require a physical test device to run properly. There are 
tentative plans to build an application/tool that allows this tool to bridge and take advantage of a physical test device.

### Install

1. Install a virtualenv
`python -m virtualenv .venv`

2. Activate it and install the requirements
`source .venv/bin/activate; pip install -r requirements.txt`

3. Run the code
`python main.py`


### TODO:
- [ ] Rewrite mocks
  - [ ] Instead of having custom python modules, consider parsing the base java libs
- [ ] !!! Add in unit tests !!!
- [ ] Rewrite instruction handling
  - [ ] Parse `NOP` alternatives (`0x0010`,`0x0020`,`0x0030`)
  - [ ] Ensure instructions are being parsed properly
- [ ] Expand coverage to allow loading of ELF/DWARF binaries
  - [ ] Emulate JNI capabilities
 
---

##### Why a platypus with a computer?

A platypus is one of the few (if not the only) mammal that lays eggs. It has physical
characteristics that contradict what mammals normally are but enough that it is still considered
a full mammal.

This tool is intended to be similar as it contradicts both static and dynamic analysis. Sometimes, you want to only execute
a single method or even just a few instructions to modify the code statically. Or you may want to run full chains of code 
that also include running native code and includes making network requests.
