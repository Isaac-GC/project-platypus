## Project Platypus

![platypus_with_computer](./extra/imgs/platypus.jpg)

This will get flushed out more in the future, allowing for more complex flows to be tracked. Currently it find and decrypt strings from a known decryption function reference.


Please note: This is in the testing phase so options may be limited and you will have to change/modify the code to adapt to new options

### Intention

This is intended to allow for a somewhat hybrid crossover between static and dynamic analysis for Android applications. While its still
very much in a heavy "work-in-progress" state → the release of it will allow for semiautomated code analysis. 

What can it be used for? 
- CI/CD tests _after_ compilation (code shouldn't but sometimes does act different after being fully compiled)
- Reverse Engineering


### AI stuffs

All AI/LLM usage in this is used to build the tool that drives the reverse engineering. It will NOT drive or 
interpret anything for you. (everything should be deterministic) 

All code was initially built in python and then ported over. I have left the initial python code here and am keeping
the rest of the python code local to prevent this from turning into or replacing androguard (major kudos and much respect to that project)

As such, it is my belief and opinion that this tool should:
  - Allow for 100% reproducible results
  - Give you as near full control of your reversing environment as possible
    - (hopefully with as many batteries included as is feasible)
  - Allow for manual work, or automation

### Limitations

Running native code is experimentally supported and will likely require a physical test device to run properly. There are 
tentative plans to build an application/tool that allows this tool to bridge and take advantage of a physical test device
or integrate directly (see: https://github.com/Isaac-GC/vardoger for current project related/status)

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
  - [ ] Support UI presentation
 
---

##### Why a platypus with a computer?

A platypus is one of the few (if not the only) mammal that lays eggs. It has physical
characteristics that contradict what mammals normally are but enough that it is still considered
a full mammal.

This tool is intended to be similar as it contradicts both static and dynamic analysis. Sometimes, you want to only execute
a single method or even just a few instructions to modify the code statically. Or you may want to run full chains of code 
that also include running native code and includes making network requests.
