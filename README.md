# SPI connection
* SPI0\_SCLK -> SCK
* SPI0\_CS0 -> SDA
* SPI0\_D0 -> MISO
* SPI0\_D1 -> MOSI

# Enabling SPI on BeagleBone
config-pin P9.17 spi_cs
config-pin P9.18 spi
config-pin P9.21 spi
config-pin P9.22 spi_sclk