# Getting started

Connecting a beaglebone black to the MFRC522:

## SPI connection
* SPI0\_SCLK -> SCK
* SPI0\_CS0  -> SDA
* SPI0\_D0   -> MISO
* SPI0\_D1   -> MOSI

## Other pins
* GND        -> GND
* 3V3        -> VCC

You can also connect the IRQ and RST pins
to GPIO pins on the beaglebone<br>
if your application requires these.

![beaglebone black pinmap](beaglebone_black_pinmap.png)
![RC522 pinmap](RC522-RFID-Reader-Writer-Module-Pinout.jpg)

## Enabling SPI on BeagleBone
* config-pin P9.17 spi\_cs
* config-pin P9.18 spi
* config-pin P9.21 spi
* config-pin P9.22 spi\_sclk
