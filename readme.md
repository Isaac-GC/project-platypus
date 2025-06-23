## Project Platypus

![platypus_with_computer](./extra/imgs/platypus.jpg)

This will get flushed out more in the future, allowing for more complex flows to be tracked. Currently it find and decrypt strings from a known decryption function reference.


Please note: This is in the testing phase so options may be limited and you will have to change/modify the code to adapt to new options


#### Install

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