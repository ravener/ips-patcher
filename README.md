# IPS Patcher

A simple IPS Patcher implemented in Python.

## Usage

```sh
usage: ips.py [-h] input patch [output]

Patch files using a .ips patch file.

positional arguments:
  input       Input file to patch
  patch       The IPS patch file to apply                               output      Output File

options:
  -h, --help  show this help message and exit
```

Example:

```sh
$ python ips.py rom.gba patch.ips
```

## License
[MIT License](LICENSE)
