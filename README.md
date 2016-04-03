# Eli.Decode
Just a tool to decode obfuscated shellcodes using the unicorn engine by DeveloppSoft(https://github.com/DeveloppSoft), original repo here(https://github.com/DeveloppSoft/Eli.Decode).

# Please note
- You may have problems or wrong decoded shellcodes...
- You need the unicorn engine (http://www.unicorn-engine.org/) AND the capstone engine (http://www.capstone-engine.org/) (with the python bindings...).

# Supported archs
- x86_32
- x86_64

# Todo
- x86_16
- arm
- arm64
- mips_3
- mips_32
- mips_32r6
- mips_64

Please note this is as easy as added / patching values in the "decoders" dictionnary, so... I just need to google it (let me time...).
Finally, please note that new architectures might be added if they are supported by the unicorn engine (http://www.unicorn-engine.org/) AND the capstone engine (http://www.capstone-engine.org/).

# Try:
```
python Eli.Decode/decoder.py --help
```

# Credits
This code is based on unicorn-decoder(https://github.com/mothran/unicorn-decoder).
Finally, I want to thanks everybody which gave me time there(https://github.com/unicorn-engine/unicorn/issues/451).

# Don't forget to contribute !!
