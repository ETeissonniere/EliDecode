# EliDecode
EliDecode is a tool to decode obfuscated shellcodes using the [unicorn-engine](https://unicorn-engine.org) for the emulation and the [capstone-engine](https://capstone-engine.org) to print the asm code.
Please note I should post news on my [website](https://developpsoft.github.io).

# Architectures
EliDecode support 6 architectures, and I will add new ones as soon as possible :smile:.
Here is the updated list:
 - x86 (16, 32 and 64 bits)
 - arm (thumb, 32 and 64 bits)

# Installing
Just install python 2 (I may upgrade it to python 3 later...) and use install.py :smile:.
For example:
```sh
sudo apt install python python-dev python-setuptools git
git clone https://github.com/DeveloppSoft/EliDecode
cd EliDecode
sudo ./install.py --unicorn --capstone
./decoder.py --help
```

# Todo
 - Change the algorithm we use to decoded (why not?)
 - Add nice colors :smile:
 - Add the ability to uninstall tools for install.py
 - Add mips and other architectures
 - Make EliDecode usable as a python module
 - Add more tests

# Contributing
You can contribute in many ways like reporting bugs, adding new features, donating...

# Credits
EliDecode is a fork of [unicorn-decoder](https://github.com/mothran/unicorn-decoder).
