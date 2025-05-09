# RFForge

This project is based on the great [RFStorm nRF24LU1+ Research Firmware](https://github.com/BastilleResearch/nrf-research-firmware).

## Description

RFForge enables both sniffing and spoofing of wireless peripherals that use proprietary protocols.  
This tool was developed as part of the thesis *Radio Based Analysis of Wireless Mice and Keyboards using Proprietary Protocols* presented at the University of Tartu.  
This project has been tested with a Crazyradio PA.  

## Installation

Refer to the [RFStorm nRF24LU1+ Research Firmware](https://github.com/BastilleResearch/nrf-research-firmware) repository for installation instructions.  

Alternatively, if you wish/need to use a virtual environment, the following can be done:  

### Install dependencies

```
sudo apt install sdcc binutils
```

### Create the virtual environment

```
python3 -m venv venv
source venv/bin/activate
```

### Install pip dependencies

```
python3 -m pip install -U -I pyusb
python3 -m pip install -U platformio
```

### Clone the project and build the firmware

```
git clone https://github.com/AgroLucas/RFForge
cd RFForge
make
```

### Flash the firmware over USB

```
sudo {path to venv}/venv/bin/python3 prog/usb-flasher/usb-flash.py bin/dongle.bin 
```

## Usage

The testing file is located at *tools/main.py*. This script instantiates the wireless devices, sets up, and launches sniffing and/or spoofing attacks.  

To run an attack, simply uncomment the corresponding line in the script and run inside the *tools* folder:  
```
./main.py
```

The exploit code is organized under the *tools/devices* directory.  
The file *device.py* defines an abstract class representing a generic device.  
Each specific device has its own implementation in its corresponding subfolder.  

### Fuzz channels

It is also possible to fuzz the channels of a device with the method: 
```
Device.fuzz_channels(device_address, device_data_rate)
```

### Sniff raw data

Raw data can be sniffed with the method: 
```
Device.quick_sniff(device_address, device_channels, device_data_rate, device_packet_size)
```

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
