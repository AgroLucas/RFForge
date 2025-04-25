# RFForge

This project is based on the great [RFStorm nRF24LU1+ Research Firmware](https://github.com/BastilleResearch/nrf-research-firmware).

## Description

RFForge enables both sniffing and spoofing of wireless peripherals that use proprietary protocols.  
This tool was developed as part of the thesis *Radio Based Analysis of Wireless Mice and Keyboards using Proprietary Protocols* presented at the University of Tartu.

## Installation

Refer to the [RFStorm nRF24LU1+ Research Firmware](https://github.com/BastilleResearch/nrf-research-firmware) repository for installation instructions.  
This project has been tested with a Crazyradio PA.

## Usage

The testing file is located at *tools/main.py*. This script instantiates the wireless devices, sets up, and launches sniffing and/or spoofing attacks.  
It is also possible to fuzz the channels of a device with the method: 
```
Device.fuzz_channels(device_address, device_data_rate)
``` 
or to sniff the raw data with the method: 
```
Device.quick_sniff(device_address, device_channels, device_data_rate, device_packet_size)
```

To run an attack, simply uncomment the corresponding line in the script and run inside the *tools* folder:  
```
./main.py
```

The exploit code is organized under the *tools/devices* directory.  
The file *device.py* defines an abstract class representing a generic device.  
Each specific device has its own implementation in its corresponding subfolder.

## Tested Devices

| Brand       | Device               | Type     | Sniffing | Spoofing |
|-------------|----------------------|----------|----------|----------|
| **Trust**   | ODY-II               | Keyboard | Yes      | Yes      |
|             | Yvi+                 | Mouse    | Yes      | No       |
| **Poss**    | PSKEY530BK           | Keyboard | Yes      | Yes      |
| **Rapoo**   | E1050                | Keyboard | Yes      | Yes      |
|             | M10                  | Mouse    | Yes      | Yes      |
| **Edenwood**| 963716 CWL01 keyboard| Keyboard | Yes      | Yes      |
|             | 963716 CWL01 mouse   | Mouse    | Yes      | Yes      |
| **Qware**   | QW PCB-238BL keyboard| Keyboard | Yes      | Yes      |
|             | QW PCB-238BL mouse   | Mouse    | Yes      | Yes      |
| **Think Xtra**| Ms6-TXn-wh         | Mouse    | Yes      | Yes      |
| **Hama**    | AKMW-100 keyboard    | Keyboard | Yes      | Yes      |
|             | AKMW-100 mouse       | Mouse    | Yes      | Yes      |
| **Omega**   | OM08WBL              | Mouse    | Yes      | Yes      |
| **HP**      | HSA-A011M            | Keyboard | No       | No       |
|             | HAS-A005K            | Mouse    | No       | No       |
| **Cherry**  | DW5100               | Keyboard | No       | Yes      |
|             | MW3000               | Mouse    | No       | Yes      |



## Credits

RFForge was originally a fork of [SySS-Research/keyjector](https://github.com/SySS-Research/keyjector), but all original code has since been removed. The current version is based solely on RFStorm.

## Disclaimer

Use at your own risk. Do not use without full consent of everyone involved. For educational purposes only.
