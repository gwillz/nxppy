nxppy
=====
nxppy is a *very* simple Python wrapper for interfacing with the excellent [NXP EXPLORE-NFC shield](http://uk.farnell.com/nxp-explore-nfc) for the [Raspberry Pi](http://www.raspberrypi.org/).  It takes NXP's NFC Reader Library and provides a thin layer for detecting a Mifare NFC tag, reading its UID (unique identifier), and reading/writing data from/to the user area.

License
=====
All files in this repository are distributed under the MIT license.

#### External components
This work was based very heavily on NXP's MifareClassic example code. The example code was only reorganized to be more conducive as an interface. NXP still retains full copyright and ownership of the example code and the NFC Reader Library. The license conditions that need to be accepted in order to use this project in conjunction with the NFC Reader Library can be found in the document [NXP_NFC_Reader_Library_licencefile.pdf](https://github.com/Schoberm/nxppy/blob/master/NXP_NFC_Reader_Library_licencefile.pdf)

Compatibility
=====
Tested with both Python 2.7 and 3.4 as installed on Raspian Jessie.

Requirements
=====
The EXPLORE-NFC card relies on SPI being enabled. Please enable SPI using raspi-config prior to installing nxppy.

#### Pin layout
Should you ever attempt to detach the Explore-NFC, here is the pin layout used by the board.

|    Name    | Physical  | BCM |
|------------|-----------|-----|
| 3V3        | 1, 17     | -   |
| V5         | 2, 4      | -   |
| GND        | 6, 9, etc | -   |
| NFC nRESET | 26        | 7   |
| NFC BUSY   | 22        | 25  |
| NFC IRQ    | 16        | 23  |
| SPI MOSI   | 19        | 10  |
| SPI MISO   | 21        | 9   |
| SPI SCLK   | 23        | 11  |
| SPI CE0    | 25        | 8   |
| I2C SDA    | 3         | 2   |
| I2C SCL    | 5         | 3   |

*Note: the 'NFC' pins must always be present. Nxppy only uses SPI so i2c can be safely ignored.*


Installation
=====
nxppy is available from PyPI.  To install, simply run:

```
sudo pip install nxppy
```

Installation will take some time as it automatically pulls down the NXP NFC Reader Library from source.

Usage
=====
Currently, the module supports ISO14443-3A/4A cards only:

```python
import nxppy

mifare = nxppy.Mifare()

# Select the first available tag and return the UID
uid = mifare.select()

# Read a single block of 4 bytes from block 10
block10bytes = mifare.read_block(10)

# Write a single block of 4 bytes
mifare.write_block(10, 'abcd')

# Get Sak, ATQA, UID
ident = mifare.get_ident()

# Get Version/manufacturer data (for NTAG compliant tags)
ntag_ver = mifare.get_version()
```

Example polling for tags:

```python
import nxppy
import time

mifare = nxppy.Mifare()

# Print card UIDs as they are detected
while True:
    try:
        uid = mifare.select()
        print(uid)
    except nxppy.SelectError:
        # SelectError is raised if no card is in the field.
        pass
        
    time.sleep(1)
```

Native Extensions
========
Nxppy includes the ability to create abstractions in pure Python code.

For example, NTAG-23xx type cards can be processed with the NTAG class, included in `nxppy/_ntag.py`.
Further abstractions can be created for different variants of the Mifare Ultralight/ISO-14443-3A/4A standard.

Feedback
=====
I welcome your feedback and pull requests!  This project started as a necessity for my own Raspberry Pi development, but I'm hoping others will find it useful as a way to quickly bootstrap NFC-based projects.  Enjoy!
