# scan-vm-residuals.ps1
# Outputs structured results and a final likelihood conclusion.
# Toggle debug output:
$global:is_debug = 1  # set to 0 to suppress detailed prints

function New-CheckResult {
    param($Name,$Flag,$Points,$Evidence)
    [PSCustomObject]@{
        Name     = $Name
        Flag     = [bool]$Flag
        Points   = [int]$Points
        Evidence = $Evidence
    }
}

function Get-VirtCapabilityStatus {
    # Return: Enabled / Disabled / Unknown
    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop
        if ($null -ne $cpu.VirtualizationFirmwareEnabled) {
            if ($cpu.VirtualizationFirmwareEnabled) { return "Enabled" } else { return "Disabled" }
        }

        # Fallback: check systeminfo text for virtualization lines
        $si = (systeminfo 2>$null) -join "`n"
        if ($si -match "Virtualization Enabled In Firmware:\s+Yes") { return "Enabled" }
        if ($si -match "Virtualization Enabled In Firmware:\s+No") { return "Disabled" }

        return "Unknown"
    } catch {
        return "Unknown"
    }
}


function timing_jitter_check {
    try {
        # ONLY flag if we're VERY confident it's a VM
        
        $extremelySuspiciousPatterns = 0
        
        # Test 1: Perfectly identical timing measurements (should NEVER happen in real hardware)
        $times = @()
        for ($i = 0; $i -lt 50; $i++) {
            $start = [System.Diagnostics.Stopwatch]::GetTimestamp()
            [System.Threading.Thread]::Sleep(0)
            $end = [System.Diagnostics.Stopwatch]::GetTimestamp()
            $times += ($end - $start)
        }
        
        $uniqueCount = ($times | Sort-Object -Unique).Count
        $totalSamples = $times.Count
        
        # In physical hardware, timing should almost never be exactly identical
        # If >80% of measurements are identical, that's extremely suspicious
        if ($totalSamples -gt 0) {
            $identicalRatio = ($totalSamples - $uniqueCount) / $totalSamples
            if ($identicalRatio -gt 0.8) {
                $extremelySuspiciousPatterns++
            }
        }
        
        # Test 2: Check for artificial timing precision
        # Real hardware timings should have some natural randomness in least significant digits
        $zeroRemainderCount = ($times | Where-Object { $_ % 100 -eq 0 }).Count
        if ($totalSamples -gt 0) {
            $zeroRemainderRatio = $zeroRemainderCount / $totalSamples
            # If too many timings end in clean numbers, suspicious
            if ($zeroRemainderRatio -gt 0.9) {
                $extremelySuspiciousPatterns++
            }
        }
        
        $evidence = [PSCustomObject]@{
            IdenticalTimingRatio = if ($totalSamples -gt 0) { [Math]::Round((($totalSamples - $uniqueCount) / $totalSamples) * 100, 2) } else { 0 }
            CleanNumberRatio = if ($totalSamples -gt 0) { [Math]::Round(($zeroRemainderCount / $totalSamples) * 100, 2) } else { 0 }
            Analysis = ""
        }
        
        if ($extremelySuspiciousPatterns -ge 2) {
            $evidence.Analysis = "Multiple extremely suspicious timing patterns detected"
            return New-CheckResult "Timing Analysis" $true 4 $evidence
        } elseif ($extremelySuspiciousPatterns -eq 1) {
            $evidence.Analysis = "One suspicious timing pattern detected"
            return New-CheckResult "Timing Analysis" $true 2 $evidence
        } else {
            $evidence.Analysis = "No suspicious timing patterns detected"
            return New-CheckResult "Timing Analysis" $false 0 $evidence
        }
        
    } catch {
        return New-CheckResult "Timing Analysis" $false 0 ("Error: " + $_.Exception.Message)
    }
}






function mac_address_spoof_check {
    try {
        $virtualOuis = @(
            "00:0C:29","00:1C:14","00:05:69","00:50:56", # VMware
            "08:00:27",                                   # VirtualBox
            "52:54:00",                                   # QEMU/KVM
            "00:16:3E"                                    # Xen
        )

        # Get an active network adapter
        $adapter = Get-CimInstance -ClassName Win32_NetworkAdapter -ErrorAction SilentlyContinue |
                   Where-Object { $_.NetConnectionStatus -eq 2 -and $_.MACAddress } |
                   Select-Object -First 1

        if (-not $adapter) {
            return New-CheckResult "MAC Address Spoof Check" $false 0 "No active network adapter found"
        }

        $mac = $adapter.MACAddress
        $macPrefix = ($mac -split '[:-]' | Select-Object -First 3) -join ':'

        # Immediate flag if MAC is a known virtual OUI
        if ($virtualOuis -contains $macPrefix) {
            $b = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue | Select-Object -First 1
            $evidence = [PSCustomObject]@{
                MAC = $mac
                AdapterManufacturer = $adapter.Manufacturer
                BaseboardManufacturer = if ($b) { $b.Manufacturer } else { $null }
                OUIMatchedVendor = "(Known virtual OUI)"
                MatchFound = $false
                Reason = "MAC prefix is a well-known virtual vendor OUI"
            }
            return New-CheckResult "MAC Address Spoof Check" $true 5 $evidence
        }

        # Lookup vendor from OUI
        try {
            $vendor = (Invoke-WebRequest -Uri "http://api.macvendors.com/$macPrefix" -UseBasicParsing -ErrorAction Stop).Content.Trim()
        } catch {
            $vendor = ""
        }

        # Get motherboard/baseboard manufacturer
        try {
            $baseboard = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction Stop | Select-Object -First 1
            $baseboardMan = if ($baseboard -and $baseboard.Manufacturer) { $baseboard.Manufacturer } else { "" }
        } catch {
            $baseboardMan = ""
        }
        
        # Helper: normalize strings
        function NormalizeVendorString($s) {
            if (-not $s) { return "" }
            $n = $s -replace '[\p{P}\p{S}]',''
            $n = $n -replace '\s+(incorporation|inc|ltd|co|corporation|corp|limited)$',''
            $n = $n -replace '\s+','' 
            return $n.ToLower()
        }

        $normVendor = NormalizeVendorString($vendor)
        $normBaseboard = NormalizeVendorString($baseboardMan)

        # If either is empty, inconclusive
        if ([string]::IsNullOrEmpty($normVendor) -or [string]::IsNullOrEmpty($normBaseboard)) {
            $evidence = [PSCustomObject]@{
                MAC = $mac
                AdapterManufacturer = $adapter.Manufacturer
                BaseboardManufacturer = $baseboardMan
                OUIMatchedVendor = $vendor
                MatchFound = $false
                Reason = "OUI lookup or baseboard manufacturer unavailable - inconclusive"
            }
            return New-CheckResult "MAC Address Spoof Check" $false 0 $evidence
        }

        # Basic fuzzy match
        $match = $false
        if ($normVendor -like "*$normBaseboard*" -or $normBaseboard -like "*$normVendor*") { $match = $true }

        # Extra known mappings
        $knownMappings = @{
            "asus" = @("asustek")
            "msi"  = @("micro-star","microstar")
            "hp"   = @("hewlettpackard","hp")
            "lenovo" = @("thinkpad")
        }

        foreach ($kb in $knownMappings.Keys) {
            $vals = $knownMappings[$kb]
            foreach ($v in $vals) {
                if ($normVendor -like "*$v*" -and $normBaseboard -like "*$kb*") { $match = $true; break }
                if ($normBaseboard -like "*$v*" -and $normVendor -like "*$kb*") { $match = $true; break }
            }
            if ($match) { break }
        }

        $flag = -not $match
        if ($flag) { $points = 5 } else { $points = 0 }

        $evidenceOut = [PSCustomObject]@{
            MAC = $mac
            AdapterManufacturer = $adapter.Manufacturer
            BaseboardManufacturer = $baseboardMan
            OUIMatchedVendor = $vendor
            NormVendor = $normVendor
            NormBaseboard = $normBaseboard
            MatchFound = $match
            Reason = if ($match) { "OUI vendor reasonably matches motherboard vendor" } else { "OUI vendor does not match motherboard vendor" }
        }

        return New-CheckResult "MAC Address Spoof Check" $flag $points $evidenceOut
    } catch {
        return New-CheckResult "MAC Address Spoof Check" $false 0 ("error:" + $_.Exception.Message)
    }
}

function HID_check {
    # Suspicious if very low number of HID devices or abnormal set
    try {
        $devs = Get-PnpDevice -Class HIDClass -ErrorAction SilentlyContinue
        if (-not $devs) { $devs = Get-PnpDevice | Where-Object { $_.FriendlyName -match "HID|keyboard|mouse" } }
        $count = if ($devs) { $devs.Count } else { 0 }
        $evidence = @{Count=$count; Sample = ($devs | Select-Object -First 10 | Select-Object FriendlyName,InstanceId) }
        # threshold: suspicious if <= 3 (adjustable)
        $flag = ($count -le 3)
        $points = if ($flag) { 2 } else { 0 }
        return New-CheckResult "HID devices low count" $flag $points $evidence
    } catch {
        return New-CheckResult "HID devices low count" $false 0 "error:$($_.Exception.Message)"
    }
}

function SetupAPI_VMW_log_check {
    # Parse setupapi.dev.log for VMware indicators
    $path = "$env:windir\INF\setupapi.dev.log"
    if (-not (Test-Path $path)) {
        return New-CheckResult "SetupAPI VMware entries" $false 0 "setupapi.dev.log not found"
    }
    $lines = Select-String -Path $path -Pattern "VMW|VMware|vmw" -SimpleMatch -ErrorAction SilentlyContinue
    $count = if ($lines) { $lines.Count } else { 0 }
    $evidence = if ($count -gt 0) { $lines | Select-Object -First 20 | ForEach-Object { $_.Line } } else { @() }
    $flag = ($count -gt 0)
    $points = if ($flag) { 2 } else { 0 }
    return New-CheckResult "SetupAPI VMware entries" $flag $points $evidence
}

function BIOS_version_date_check {
    try {
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
        $manufacturer = $bios.Manufacturer
        $version = $bios.SMBIOSBIOSVersion
        $release = $bios.ReleaseDate
        $evidence = @{Manufacturer=$manufacturer;Version=$version;ReleaseDate=$release}
        $flag = ($manufacturer -match "VMware|VirtualBox|Xen|QEMU")
        $points = if ($flag) { 4 } else { 0 }
        return New-CheckResult "BIOS vendor/version" $flag $points $evidence
    } catch {
        return New-CheckResult "BIOS vendor/version" $false 0 "error:$($_.Exception.Message)"
    }
}

function display_adapter_type_check {
    try {
        $gpus = Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop
        $evidence = $gpus | Select-Object Name,DriverVersion,VideoProcessor,AdapterRAM

        # Combine both the Name and VideoProcessor into a single string for searching
        $searchableText = ($gpus | Select-Object -Property @{Name="Text"; Expression={"$($_.Name) $($_.VideoProcessor)"}} | Select-Object -ExpandProperty Text) -join " "
        
        $flag = ($searchableText -match "VMware|SVGA|Virtual|VBox|VBoxVideo|VMware SVGA|VMware SVGA II")
        $points = if ($flag) { 3 } else { 0 }
        return New-CheckResult "Display adapter type" $flag $points $evidence
    } catch {
        return New-CheckResult "Display adapter type" $false 0 "error:$($_.Exception.Message)"
    }
}

function pnp_pointing_device_id_check {
    try {
        # Specifically target devices in the Pointer class, like in System Information
        $items = Get-PnpDevice -Class Pointer -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -imatch "VMW|VMWARE|VMCI|QEMU|VirtualBox" }
        
        $count = if ($items) { $items.Count } else { 0 }
        $evidence = if ($items) { $items | Select-Object -First 20 FriendlyName,InstanceId,Class,Status } else { @() }
        
        $flag = ($count -gt 0)
        $points = if ($flag) { 4 } else { 0 }
        
        return New-CheckResult "PNP Pointing Device ID contains VM indicator" $flag $points $evidence
    } catch {
        return New-CheckResult "PNP Pointing Device ID contains VM indicator" $false 0 "error:$($_.Exception.Message)"
    }
}

function virtual_monitor_manager_check {
    try {
        $mon = Get-CimInstance -ClassName Win32_DesktopMonitor -ErrorAction SilentlyContinue
        if (-not $mon) { $mon = @() }
        $missingMeta = $mon | Where-Object { ([string]::IsNullOrEmpty($_.Name)) -or ([string]::IsNullOrEmpty($_.MonitorType)) }
        $flag = ($missingMeta.Count -gt 0)
        $evidence = $mon | Select-Object Name,MonitorType,PNPDeviceID,ScreenWidth,ScreenHeight
        $points = if ($flag) { 1 } else { 0 }
        return New-CheckResult "Virtual monitor metadata missing" $flag $points $evidence
    } catch {
        return New-CheckResult "Virtual monitor metadata missing" $false 0 "error:$($_.Exception.Message)"
    }
}

function suspicious_vm_drivers_check {
    # Only suspicious when CPU virtualization is reported Disabled/Unknown AND vm*.sys drivers exist
    try {
        $virtStatus = Get-VirtCapabilityStatus
        $vmDrivers = Get-ChildItem -Path "$env:windir\system32\drivers" -Filter "vm*.sys" -ErrorAction SilentlyContinue
        $count = if ($vmDrivers) { $vmDrivers.Count } else { 0 }
        $evidence = @{VirtStatus=$virtStatus;Drivers = ($vmDrivers | Select-Object Name,LastWriteTime) }
        $flag = ($virtStatus -eq "Disabled" -and $count -gt 0)
        $points = if ($flag) { 3 } else { 0 }
        return New-CheckResult "VM drivers present while virtualization disabled" $flag $points $evidence
    } catch {
        return New-CheckResult "VM drivers present while virtualization disabled" $false 0 "error:$($_.Exception.Message)"
    }
}

# Initialize score and results array
$vmScore = 0
$results = @()
# List of all checks to run
$checkFunctions = @(
    { HID_check },
    { SetupAPI_VMW_log_check },
    { BIOS_version_date_check },
    { display_adapter_type_check },
    { pnp_pointing_device_id_check },
    { virtual_monitor_manager_check },
    { suspicious_vm_drivers_check },
    { mac_address_spoof_check },
    { timing_jitter_check }
)


foreach ($checkFunction in $checkFunctions) {

    $resultObject = & $checkFunction


    $vmScore += $resultObject.Points


    $results += $resultObject
}


if ($global:is_debug -eq 1) {
    Write-Host "`n=== Detailed Check Results ===`n"
    $results | ForEach-Object {
        Write-Host "Name: $($_.Name)"
        Write-Host "Flagged: $($_.Flag)    Points: $($_.Points)"
        if ($_.Evidence -is [string]) {
            Write-Host "Evidence: $($_.Evidence)"
        } elseif ($_.Evidence -is [array] -or $_.Evidence -is [System.Object]) {
            try {
                $evidenceArray = @($_.Evidence)  # Ensure it's always an array
                foreach ($item in $evidenceArray) {
                    if ($item -is [System.Management.Automation.PSCustomObject] -or $item -is [CimInstance]) {
                        $props = $item | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
                        foreach ($prop in $props) {
                            $val = $item.$prop
                            Write-Host ("  {0,-25}: {1}" -f $prop, $val)
                        }
                        Write-Host "  ---------------------------"
                    } else {
                        Write-Host "  $item"
                    }
                }
            } catch {
                Write-Host "  (couldn't format evidence)"
            }
        }
        Write-Host "---------------------------"
    }
}


if ($vmScore -le 3) {
    $conclusion = "Minimal"
} elseif ($vmScore -le 6) {
    $conclusion = "Small"
} elseif ($vmScore -le 8) {
    $conclusion = "Medium"
} elseif ($vmScore -le 10) {
    $conclusion = "Moderate"
} elseif ($vmScore -le 12) {
    $conclusion = "High"
} elseif ($vmScore -le 14) {
    $conclusion = "Very High"
} else {
    $conclusion = "Extremely High"
}

Write-Host "`nVirtual Environment Likelihood: $conclusion ($vmScore points)"
Write-Host "Press any key to exit..."
[Console]::ReadKey($true) | Out-Null

