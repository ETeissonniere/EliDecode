# Eli.Decode
THE tool to decode obfuscated shellcodes using the unicorn engine by [DeveloppSoft](https://github.com/DeveloppSoft), original repo [here](https://github.com/DeveloppSoft/Eli.Decode).
It currently support 6 architectures and more arecoming (see the TODO list) !!
Check the [website](https://developpsoft.github.io/EliDecode/).


# Install
```
git clone https://github.com/unicorn-engine/unicorn
cd unicorn
sudo ./make.sh install
cd bindings/python
sudo make install

cd ../..

git clone https://github.com/aquynh/capstone
cd capstone
sudo ./make.sh install
cd bindings/python
make install

cd ../..

git clone https://github.com/DeveloppSoft/EliDecode
cd EliDecode
python decoder.py --help
```


# Usage
## Coming soon...


# Contribting
You can contribute to EliDecode by:
## Donating
If you like my work, please considermaking a donation (button coming soon).
## Coding
Please do pull requests to improve EliDecode by adding to features.
## Reporting
If you have problems with EliDecode please open an issue.
## Ideas
If you know how to improve EliDecode but don't know how to do it, don't hesistate to open an issue!
## Sharing and promoting
You can share EliDecode if you want (under the terms of the license), for example by speaking about it on your website or making videos.
## Everything else...
There is many unquoted ways to contribute...


# TODO
- [x] x86_16
- [x] x86_32
- [x] x86_64
- [x] arm_thumb
- [x] arm32
- [x] arm64
- [ ] mips_3
- [ ] mips_32
- [ ] mips_32r6
- [ ] mips_64


# Credits
This code is based on unicorn-decoder. Finally, I want to thanks everybody which gave me time there.


# Contributors
- DeveloppSoft: project's owner (https://github.com/DeveloppSoft).
- Nguyen Anh Quynh: fixed markdown, madethe capstone and unicorn engines (https://github.com/aquynh).
