# VMwareHardenedLoader residual vulnerabilities

## About & Credit
Sanitized audit findings from isolated-lab testing — research and defensive purposes only. No PoCs.
**Fork of:** [hzqst/VmwareHardenedLoader](https://github.com/hzqst/VmwareHardenedLoader)

## Purpose
The purpose of this repo is to document remaining traces of a VM post-spoof. It's intended use is to be used as a template for security research and defensive analysis. This does not cover all possible remaining traces, it focuses on the common, easily identifiable traces that exist post-spoofing when using the upstream repo's guide. All testing was performed in isolated lab environments and no exploit code or PoCs are included.

## Scope
All testing was done on a Windows 10 22H2 Virtual Machine, following the upstream repository's instructions.

### Information:
- VM OS: Microsoft Windows 10 Pro 22H2 19045.3803
- Host OS: Microsoft Windows 10 Pro 22H2 19045.6456
- VMware Workstation v7.6.4-24832109

___


# **Findings**

| Vulnerability | Location | Photo| Notes| Extra Photo |
| --------------| -------- | ---- | ---- | ----------- |
| Unusually low number of Human Interface Devices             | Device Manager        |  ![HID](Screenshots/HID.png)   | No regular machine has such a low amount of HIDs. Here is an image of a fresh windows 10 install for reference. | ![HID Reference](Screenshots/HID_reference.png)
| Recent 'Device Started' Timestamp             | Device Manager (Events tab for a device)        | ![Timestamps](Screenshots/Timestamps.png)    | When all devices have the same timestamp/very slightly varied, it is usually an indicative of a VM if the timestamp is recent. | N/A
| Wrong Driver Provider             | Device Manager        | ![Wrong Service Provider](Screenshots/wrong_driver_provider.png)    | A photo of my fresh install PC for reference. | ![Wrong Service Provider Reference](Screenshots/wrong_driver_provider_reference.png)
| Virtualisation Drivers while CPU is stated to be incapable of virtualisation             | C:\Windows\System32\drivers        | ![VM Drivers](Screenshots/vm_drivers.png)    | When a system is incapable of virtualisation, yet has a number of virtualisation-related drivers, it can be an indicator of a spoofed VM. | ![Incapable of Virtualization](Screenshots/virtualisation_incapable.png)
| BIOS Version/Date             | System Information        | ![BIOS Version](Screenshots/bios_version.png)    |
| Display Adapter Type             | System Information -> Components -> Adapter Type        | ![Adapter Type](Screenshots/adapter_type.png)    |
| PNP Device ID "VMW" (VMware)             | System Information -> Components -> PNP Device ID        | ![PNP Device ID](Screenshots/pnp_device_id.png)    |
| Virtual Monitor Manager (+ no version or manufacturer info)             | Software Environments -> Loaded Modules        | ![Virtual Monitor Manager](Screenshots/virtualmonitormanager.png)    |


___


## **Analysis & Interpretation**
The collected artifacts show that even after following the full spoofing guide from the upstream repository, numerous identifiable traces of virtualization remain. The residual indicators range from inconsistencies in hardware, as well as driver and timestamp anomalies.

### General Overview
Post spoof, the system presents itself as a regular windows 10 installation, but a closer look reveals a number of discrepencies and mismatches that collectively udnermine the effectiveness of the spoof. These findings indicate that VMware's and Windows' internal device management still expose patterns unique to virtualized machines.

### 1. Anomalies in Hardware Enumeration
The low number of HIDs is one of the clearest signs which are not software-based. Physical systems normally enumerate multiple HID entries for controllers of keyboards, mice, touchpads, and additional I/O interfaces, while virtual environments pack many of these into a single layer, causing an unusually small HID list. This remains a **medium-confidence indicator** of virtualisation.

### 2. Temporal Consistency
Identical, or near identical "Device Started" timestamps across system components hint that devices were initialized simultaneously during the same session, which is a pattern not commonly observed on a real machine, where drivers and devices initialize over time due to software and driver updates, as well as hardware upgrades. This is a **moderate-strength indicator**, as while it is not exclusive to virtual environments, it is a strong context clue when paired with other findings.

### 3. Driver Provider Mismatch
The mismatch in driver provider names (such as VMware or unidentified providers appearing where Microsoft or OEMs should) suggests remnant
