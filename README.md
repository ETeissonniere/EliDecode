# Eli.Decode
Just a tool to decode obfuscated shellcodes using the unicorn engine

# Supported archs
- x86_32

# Todo
- x86_16
- x86_64
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

# Don't forget to contribute !!
