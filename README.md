# IPS Patcher

A simple IPS Patcher implemented in Python.

## Usage

If you have [Python](https://www.python.org/) installed, you can simply run the [ips.py](ips.py) file directly, or [download a bundled release](https://github.com/ravener/ips-patcher/releases) to run standalone without having to install python.

```sh
usage: ips.py [-h] input patch [output]

Patch files using a .ips patch file.

positional arguments:
  input       Input file to patch
  patch       The IPS patch file to apply
  output      Output File

options:
  -h, --help  show this help message and exit
```

Example:

```sh
$ python ips.py rom.gba patch.ips
```

## License

[MIT License](LICENSE)
