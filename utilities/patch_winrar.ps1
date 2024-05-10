
param (
	[Parameter(Mandatory)][string]$File
)

Set-Location $PSScriptRoot

###########
# Options #
###########

$string = @"
<head><meta http-equiv="X-UA-Compatible" content="IE=Edge"><meta http-equiv="content-type" content="text/html; charset=`0
"@

# This is where the code references the hardcoded header string.
# Needs to be updated if the WinRAR version is changed.
$patchOffset = 0x11EC3

#########
# Patch #
#########

Write-Output "    Fixing WinRAR self-extracting archive start delay / no text bug..."

# Read file bytes
$bytes = [System.IO.File]::ReadAllBytes($File)

###################
# Parse PE Header #
###################

$peSignatureOffset = [System.BitConverter]::ToUInt32($bytes, 0x3C)
$sectionCount = [System.BitConverter]::ToUInt16($bytes, $peSignatureOffset + 0x6)
$optionalHeaderSize = [System.BitConverter]::ToUInt16($bytes, $peSignatureOffset + 0x14)

if ($optionalHeaderSize -eq 0) {
	Write-Output "      Missing optional header - aborting!"
	return
}

$optionalHeaderOffset = $peSignatureOffset + 0x18
$optionalHeaderMagic = [System.BitConverter]::ToUInt16($bytes, $optionalHeaderOffset)

if ($optionalHeaderMagic -eq 0x10B) {
	$imageBase = [System.BitConverter]::ToUInt32($bytes, $optionalHeaderOffset + 28)
}
elseif ($optionalHeaderMagic -eq 0x20B) {
	$imageBase = [System.BitConverter]::ToUInt64($bytes, $optionalHeaderOffset + 24)
}
else {
	Write-Output "      Unknown PE format type - aborting!"
}

############################
# Parse PE Section Headers #
############################

$stringBytes = [System.Text.Encoding]::Unicode.GetBytes($string)
$stringBytesLen = $stringBytes.Length

$sectionTableOffset = $optionalHeaderOffset + $optionalHeaderSize
$found = 0

# Find a section that has enough alignment space at the end to write the patch string
for ($i = 0; $i -lt $sectionCount; $i++) {

	$sectionOffset = $sectionTableOffset + 0x28 * $i
	$sectionFlags = [System.BitConverter]::ToUInt32($bytes, $sectionOffset + 0x24)

	# Readable
	if ($sectionFlags -band 0x40000000 -eq 0) {
		continue
	}

	$virtualSize  = [System.BitConverter]::ToUInt32($bytes, $sectionOffset + 0x8)
	$sizeOfRawData = [System.BitConverter]::ToUInt32($bytes, $sectionOffset + 0x10)
	$freeSpace = $sizeOfRawData - $virtualSize

	if ($freeSpace -ge $stringBytesLen) {
		$found = 1
		break
	}
}

if ($found -eq 0) {
	Write-Output "      Not enough free space to write patch string (needed $stringBytesLen bytes) - aborting!"
}

$sectionName = [System.Text.Encoding]::ASCII.GetString($bytes, $sectionOffset, 8).Trim("`0")
$virtualAddress = [System.BitConverter]::ToUInt32($bytes, $sectionOffset + 0xC)
$pointerToRawData = [System.BitConverter]::ToUInt32($bytes, $sectionOffset + 0x14)

$usedRawSize = $sizeOfRawData - $freeSpace
$insertAddress = $imageBase + $virtualAddress + $usedRawSize
$insertOffset = $pointerToRawData + $usedRawSize

###############
# Write Patch #
###############

Write-Output "      Writing patch string to the end of section `"$sectionName`" at 0x$($insertOffset.ToString("X"))..."

foreach ($byte in $stringBytes) {
	$bytes[$insertOffset++] = $byte
}

Write-Output "      Writing reference to patch string in code at 0x$($patchOffset.ToString("X"))..."

foreach ($byte in [System.BitConverter]::GetBytes($insertAddress)) {
	$bytes[$patchOffset++] = $byte
}

[System.IO.File]::WriteAllBytes($File, $bytes)
