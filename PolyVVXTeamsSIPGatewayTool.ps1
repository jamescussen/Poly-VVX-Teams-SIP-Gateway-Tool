########################################################################
# Name: Poly VVX Teams SIP Gateway Tool
# Version: v1.0.0 (11/2/2022)
# Original Release Date: 11/2/2022
# Created By: James Cussen
# Web Site: https://www.myteamslab.com
# Notes: For more information on the requirements for setting up and using this tool please visit http://www.myteamslab.com
#
# Copyright: Copyright (c) 2022, James Cussen (www.myteamslab.com) All rights reserved.
# Licence: 	Redistribution and use of script, source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#				1) Redistributions of script code must retain the above copyright notice, this list of conditions and the following disclaimer.
#				2) Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#				3) Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#				4) This license does not include any resale or commercial use of this software.
#				5) Any portion of this software may not be reproduced, duplicated, copied, sold, resold, or otherwise exploited for any commercial purpose without express written consent of James Cussen.
#			THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; LOSS OF GOODWILL OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Pre-requisistes:
#		- Poly VVX Phones.
#		- You will need direct access over the network to the subnets where the phones are deployed (no firewalls blocking web ports) and access to the Internet for connections to Microsoft's provisioning service (via TCP Port 443).
#
# Command Line Options:
#
# -Command
#	If you specify a command then the tool will not load the GUI and instead will execute the command directly and respond with an output object.
#
#	Values: status, signin, signout, provision, changepassword, restart
#
#	Example: .\PolyVVXTeamsSIPGatewayTool.ps1 -DeviceIPRange @("10.0.0.141", "10.0.0.238") -DeviceAdminPassword "P@ssw0rd" -DeviceUseHTTPS $true -Command status
#	Output Object Format:
#
#		IPAddress  : 10.0.0.238
#		Model      : VVX 411
#		MACAddress : 64:16:7F:25:12:88
#		Version    : 6.3.1.8427
#		Result     : Provisioned and signed out
#
# Note: Some commands will not give outputs for the Model, MACAddress and Version values. They will respond with a blank string ("") if there is no data available
#
# -DeviceWebPort
#	This is the web port on the phone device. The tool will try to connect to this port to get to the web interface.
#	Values: 1-65535
#
# -DeviceUseHTTPS
#	This specifies if HTTP or HTTPS is used to connect to the device. $true or $false
#	Values: $true or $false
#
# -DeviceAdminUsername
#	This specifies the admin username on the VVX. This should always be "Polycom"
#	Values: "Polycom" - Don't change this unless you know something I don't.
#
# -DeviceAdminPassword
#	This specifies the admin password for the VVX web interface.
#	Values: Default "456". Any string is valid.
#
# -DeviceIPRange
#	This specifies an array object containing and IP Address, IP Address range in subnet format (10.0.0.1/24), or IP Range in dashed format (e.g 10.0.0.1-10.0.0.254)
#	Value: Array format (e.g @() format). Examples:
# 		-DeviceIPRange @("10.0.0.238", "10.0.0.141")
#  		-DeviceIPRange @("192.168.0.200/24", "192.168.1.10/24")
#		-DeviceIPRange @("192.168.0.200-192.168.0.220", "192.168.1.10-192.168.1.20")
#
# -DeviceRegion
#	This is the region where the phones are being deployed. You should use your local region for best performance.
#	Values: "Asia Pacific", "Europe", "America"
#
# -DeviceNewPassword
#	This setting can be used to send the new password when using the "changepassword" Command flag.
#
# Known Issues: 
#
# Release Notes:
# 1.00 Initial Release.
#	- 
#
########################################################################

[CmdletBinding()] 
param (
[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
[ValidateNotNullOrEmpty()]
[string] $DeviceWebPort,

[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
[ValidateNotNullOrEmpty()]
[string] $DeviceUseHTTPS,

[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
[ValidateNotNullOrEmpty()]
[string] $DeviceAdminUsername,

[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
[ValidateNotNullOrEmpty()]
[string] $DeviceAdminPassword,

[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
[ValidateNotNullOrEmpty()]
[Array] $DeviceIPRange,

[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
[ValidateNotNullOrEmpty()]
[string] $Command,

[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
[ValidateNotNullOrEmpty()]
[string] $DeviceRegion,

[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
[ValidateNotNullOrEmpty()]
[string] $DeviceNewPassword
)


$theVersion = $PSVersionTable.PSVersion
$MajorVersion = $theVersion.Major
$MinorVersion = $theVersion.Minor

$OS = [environment]::OSVersion
if($OS -match "Windows")
{
	Write-Host "This is a Windows Machine. CHECK PASSED!" -foreground "green"
}
else
{
	Write-Host "This is not a Windows machine. You're in untested territory, good luck. If it doesn't work, try Windows." -foreground "Yellow"	
}

$DotNetCoreCommands = $false
Write-Host ""
Write-Host "--------------------------------------------------------------"
Write-Host "Powershell Version Check..." -foreground "yellow"
Write-Host "Powershell Version ${MajorVersion}.${MinorVersion}" -foreground "yellow"
if($MajorVersion -eq  "1")
{
	Write-Host "This machine only has Version 1 Powershell installed.  This version of Powershell is not supported." -foreground "red"
	exit
}
elseif($MajorVersion -eq  "2")
{
	Write-Host "This machine has Version 2 Powershell installed. This version of Powershell is not supported." -foreground "red"
	exit
}
elseif($MajorVersion -eq  "3")
{
	Write-Host "This machine has version 3 Powershell installed. CHECK PASSED!" -foreground "green"
}
elseif($MajorVersion -eq  "4")
{
	Write-Host "This machine has version 4 Powershell installed. CHECK PASSED!" -foreground "green"
}
elseif($MajorVersion -eq  "5")
{
	Write-Host "This machine has version 5 Powershell installed. CHECK PASSED!" -foreground "green"
}
elseif($MajorVersion -eq  "6")
{
	Write-Host "ERROR: This machine has version 6 Powershell installed. It's recommended that you upgrade to a minimum of Version 7" -foreground "red"
	exit
}
elseif($MajorVersion -eq  "7")
{
	Write-Host "This machine has version 7 Powershell installed. CHECK PASSED!" -foreground "green"
	$DotNetCoreCommands = $true
}
else
{
	Write-Host "This machine has version ${MajorVersion}.${MinorVersion} of Powershell installed. This tool in GUI mode is not supported with this version. Try command line mode instead." -foreground "red"
	exit
}
Write-Host "--------------------------------------------------------------"
Write-Host ""


# HTTP default is "80", and HTTPS default is "443"
$script:WebPort = "443"
if($DeviceWebPort -ne $null -and $DeviceWebPort -ne "")
{
	Write-Host "INFO: Using command line DeviceWebPort setting = $DeviceWebPort" -foreground "Yellow"
	$script:WebPort = $DeviceWebPort
}

$script:WebServicePort = "443"
if($DeviceWebPort -ne $null -and $DeviceWebPort -ne "")
{
	$script:WebServicePort = $DeviceWebPort
}


#setting $true will make web interface connections use https:// 
$script:UseHTTPS = $true
if($DeviceUseHTTPS.ToLower() -eq "true")
{
	Write-Host "INFO: Using command line DeviceUseHTTPS setting = $DeviceUseHTTPS" -foreground "Yellow"
	$script:UseHTTPS = $true
}
elseif($DeviceUseHTTPS.ToLower() -eq "false")
{
	Write-Host "INFO: Using command line DeviceUseHTTPS setting = $DeviceUseHTTPS" -foreground "Yellow"
	$script:UseHTTPS = $false
}


# Examples:
# $script:IPRanges = @("192.168.0.200-192.168.0.220", "192.168.1.10-192.168.1.20")
# $script:IPRanges = @("192.168.0.200/24", "192.168.1.10/24")
# $script:IPRanges = @("10.0.0.238", "10.0.0.141")
[Array] $script:IPRanges = @()
if($DeviceIPRange -ne $null)
{
	if($DeviceIPRange.Length -gt 0)
	{
		Write-Host "INFO: Using command line DeviceIPRange setting = $DeviceIPRange" -foreground "Yellow"
		if($DeviceIPRange.Length -gt 1) #CHECK THERE ARE MULTIPLE
		{
			#$Ranges = $DeviceIPRange -split ","
			
			foreach($Range in $DeviceIPRange)
			{
				if($Range.Contains("/")) #CHECK SUBNET FORMAT
				{
					$IPRangeSplit = $Range -split "/"
					[string]$Network = $IPRangeSplit[0]
					if($Network -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
					{
						[string]$Mask = $IPRangeSplit[1]
						
						if($Mask -match "^([0-9]|[1-2][0-9]|30)$")
						{
							Write-Host "INFO: IP Range format accepted." -foreground "Yellow"
							$script:IPRanges += @($Range)								
						}
						else
						{
							Write-Host "ERROR: IP Range not in correct format. Bad subnet mask." -foreground "red"
						}
					}
					else
					{
						Write-Host "ERROR: IP Range not in correct format. Bad network address." -foreground "red"
					}
				}
				elseif($Range.Contains("-")) #CHECK FOR ALTERNATE FORMAT
				{
					$IPRangeSplit = $Range -split "-"
					if($IPRangeSplit[0] -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b" -and $IPRangeSplit[1] -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
					{
						Write-Host "INFO: IP Range format accepted." -foreground "Yellow"
						$script:IPRanges += @($Range)
					}
					else
					{
						Write-Host "ERROR: IP Range not in correct format." -foreground "red"
					}
				}
				elseif($DeviceIPRange -match "^(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])$")
				{
					$script:IPRanges = @($DeviceIPRange)
				}
				else
				{
					Write-Host "ERROR: IP Range not in correct format." -foreground "red"
				}
			}
		}
		else
		{
			if($DeviceIPRange[0].Contains("/")) #CHECK SUBNET FORMAT
			{
				$IPRangeSplit = $DeviceIPRange[0] -split "/"
				[string]$Network = $IPRangeSplit[0]
				if($Network -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
				{
					[string]$Mask = $IPRangeSplit[1]
					
					if($Mask -match "^([0-9]|[1-2][0-9]|30)$")
					{
						$script:IPRanges = @($DeviceIPRange)								
					}
					elseif($DeviceIPRange -match "^(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])$")
					{
						$script:IPRanges = @($DeviceIPRange)
					}
					else
					{
						Write-Host "ERROR: IP Range not in correct format. Bad subnet mask." -foreground "red"
					}
				}
				else
				{
					Write-Host "ERROR: IP Range not in correct format. Bad network address." -foreground
				}
			}
			elseif($DeviceIPRange[0].Contains("-")) #CHECK FOR ALTERNATE FORMAT
			{
				$IPRangeSplit = $DeviceIPRange[0] -split "-"
				if($IPRangeSplit[0] -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b" -and $IPRangeSplit[1] -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
				{
					Write-Host "INFO: IP Range format accepted." -foreground "Yellow"
					$script:IPRanges = @($DeviceIPRange)
				}
				else
				{
					Write-Host "ERROR: IP Range not in correct format." -foreground "red"
				}
			}
			elseif($DeviceIPRange -match "^(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])$")
			{
				$script:IPRanges = @($DeviceIPRange)
			}
			else
			{
				Write-Host "ERROR: IP Range not in correct format." -foreground "red"
			}
		}
	}
}

$script:AdminUsername = "Polycom"
if($DeviceAdminUsername -ne $null -and $DeviceAdminUsername -ne "")
{
	Write-Host "INFO: Using command line DeviceAdminUsername setting = $DeviceAdminUsername" -foreground "Yellow"
	$script:AdminUsername = $DeviceAdminUsername
}

$script:AdminPassword = "456"
if($DeviceAdminPassword -ne $null -and $DeviceAdminPassword -ne "")
{
	Write-Host "INFO: Using command line DeviceAdminPassword setting = $DeviceAdminPassword" -foreground "Yellow"
	$script:AdminPassword = $DeviceAdminPassword
}

$ProvisioningURLTable = @{"Asia Pacific"="apac.ipp.sdg.teams.microsoft.com"; "America"="noam.ipp.sdg.teams.microsoft.com"; "Europe"="emea.ipp.sdg.teams.microsoft.com"}
$script:Region = "Asia Pacific"
if($DeviceRegion -ne $null -and $DeviceRegion -ne "")
{
	Write-Host "INFO: Using command line Region setting = $DeviceRegion" -foreground "Yellow"
	$script:Region = $DeviceRegion
}

$script:NewPassword = "12345"
if($DeviceNewPassword -ne $null -and $DeviceNewPassword -ne "")
{
	Write-Host "INFO: Using command line DeviceNewPassword setting = $DeviceNewPassword" -foreground "Yellow"
	$script:NewPassword = $DeviceNewPassword
}


$OpenUI = $true
#Check if a action is requested from command line
if($Command.ToLower() -eq "signin")
{
	Write-Host "INFO: signin" -foreground "Yellow"
	$OpenUI = $false
}
elseif($Command.ToLower() -eq "signout")
{
	Write-Host "INFO: signout" -foreground "Yellow"
	$OpenUI = $false
}
elseif($Command.ToLower() -eq "status")
{
	Write-Host "INFO: status" -foreground "Yellow"
	$OpenUI = $false
}
elseif($Command.ToLower() -eq "provision")
{
	Write-Host "INFO: provision" -foreground "Yellow"
	$OpenUI = $false
}
elseif($Command.ToLower() -eq "changepassword")
{
	Write-Host "INFO: changepassword" -foreground "Yellow"
	$OpenUI = $false
}
elseif($Command.ToLower() -eq "restart")
{
	Write-Host "INFO: restart" -foreground "Yellow"
	$OpenUI = $false
}
else
{
	#NOTHING
}

if(!$DotNetCoreCommands) #PowerShell 7 doesn't like this using -SkipCertificateCheck instead
{
add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;

            public class IDontCarePolicy : ICertificatePolicy {
            public IDontCarePolicy() {}
            public bool CheckValidationResult(
                ServicePoint sPoint, X509Certificate cert,
                WebRequest wRequest, int certProb) {
                return true;
            }
        }
"@
[System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy
}
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

if($OpenUI) #LOAD UI START
{

# Set up the form  ============================================================

[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 

$objForm = New-Object System.Windows.Forms.Form 
$objForm.Text = "Poly VVX - Teams SIP Gateway Tool 1.00"
$objForm.Size = New-Object System.Drawing.Size(430,370) 
$objForm.MinimumSize = New-Object System.Drawing.Size(430,370) 
$objForm.StartPosition = "CenterScreen"
#Myteamslab Icon
[byte[]]$WindowIcon = @(71, 73, 70, 56, 57, 97, 32, 0, 32, 0, 231, 137, 0, 0, 52, 93, 0, 52, 94, 0, 52, 95, 0, 53, 93, 0, 53, 94, 0, 53, 95, 0,53, 96, 0, 54, 94, 0, 54, 95, 0, 54, 96, 2, 54, 95, 0, 55, 95, 1, 55, 96, 1, 55, 97, 6, 55, 96, 3, 56, 98, 7, 55, 96, 8, 55, 97, 9, 56, 102, 15, 57, 98, 17, 58, 98, 27, 61, 99, 27, 61, 100, 24, 61, 116, 32, 63, 100, 36, 65, 102, 37, 66, 103, 41, 68, 104, 48, 72, 106, 52, 75, 108, 55, 77, 108, 57, 78, 109, 58, 79, 111, 59, 79, 110, 64, 83, 114, 65, 83, 114, 68, 85, 116, 69, 86, 117, 71, 88, 116, 75, 91, 120, 81, 95, 123, 86, 99, 126, 88, 101, 125, 89, 102, 126, 90, 103, 129, 92, 103, 130, 95, 107, 132, 97, 108, 132, 99, 110, 134, 100, 111, 135, 102, 113, 136, 104, 114, 137, 106, 116, 137, 106,116, 139, 107, 116, 139, 110, 119, 139, 112, 121, 143, 116, 124, 145, 120, 128, 147, 121, 129, 148, 124, 132, 150, 125,133, 151, 126, 134, 152, 127, 134, 152, 128, 135, 152, 130, 137, 154, 131, 138, 155, 133, 140, 157, 134, 141, 158, 135,141, 158, 140, 146, 161, 143, 149, 164, 147, 152, 167, 148, 153, 168, 151, 156, 171, 153, 158, 172, 153, 158, 173, 156,160, 174, 156, 161, 174, 158, 163, 176, 159, 163, 176, 160, 165, 177, 163, 167, 180, 166, 170, 182, 170, 174, 186, 171,175, 186, 173, 176, 187, 173, 177, 187, 174, 178, 189, 176, 180, 190, 177, 181, 191, 179, 182, 192, 180, 183, 193, 182,185, 196, 185, 188, 197, 188, 191, 200, 190, 193, 201, 193, 195, 203, 193, 196, 204, 196, 198, 206, 196, 199, 207, 197,200, 207, 197, 200, 208, 198, 200, 208, 199, 201, 208, 199, 201, 209, 200, 202, 209, 200, 202, 210, 202, 204, 212, 204,206, 214, 206, 208, 215, 206, 208, 216, 208, 210, 218, 209, 210, 217, 209, 210, 220, 209, 211, 218, 210, 211, 219, 210,211, 220, 210, 212, 219, 211, 212, 219, 211, 212, 220, 212, 213, 221, 214, 215, 223, 215, 216, 223, 215, 216, 224, 216,217, 224, 217, 218, 225, 218, 219, 226, 218, 220, 226, 219, 220, 226, 219, 220, 227, 220, 221, 227, 221, 223, 228, 224,225, 231, 228, 229, 234, 230, 231, 235, 251, 251, 252, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 33, 254, 17, 67, 114, 101, 97, 116, 101, 100, 32, 119, 105, 116, 104, 32, 71, 73, 77, 80, 0, 33, 249, 4, 1, 10, 0, 255, 0, 44, 0, 0, 0, 0, 32, 0, 32, 0, 0, 8, 254, 0, 255, 29, 24, 72, 176, 160, 193, 131, 8, 25, 60, 16, 120, 192, 195, 10, 132, 16, 35, 170, 248, 112, 160, 193, 64, 30, 135, 4, 68, 220, 72, 16, 128, 33, 32, 7, 22, 92, 68, 84, 132, 35, 71, 33, 136, 64, 18, 228, 81, 135, 206, 0, 147, 16, 7, 192, 145, 163, 242, 226, 26, 52, 53, 96, 34, 148, 161, 230, 76, 205, 3, 60, 214, 204, 72, 163, 243, 160, 25, 27, 62, 11, 6, 61, 96, 231, 68, 81, 130, 38, 240, 28, 72, 186, 114, 205, 129, 33, 94, 158, 14, 236, 66, 100, 234, 207, 165, 14, 254, 108, 120, 170, 193, 15, 4, 175, 74, 173, 30, 120, 50, 229, 169, 20, 40, 3, 169, 218, 28, 152, 33, 80, 2, 157, 6, 252, 100, 136, 251, 85, 237, 1, 46, 71,116, 26, 225, 66, 80, 46, 80, 191, 37, 244, 0, 48, 57, 32, 15, 137, 194, 125, 11, 150, 201, 97, 18, 7, 153, 130, 134, 151, 18, 140, 209, 198, 36, 27, 24, 152, 35, 23, 188, 147, 98, 35, 138, 56, 6, 51, 251, 29, 24, 4, 204, 198, 47, 63, 82, 139, 38, 168, 64, 80, 7, 136, 28, 250, 32, 144, 157, 246, 96, 19, 43, 16, 169, 44, 57, 168, 250, 32, 6, 66, 19, 14, 70, 248, 99, 129, 248, 236, 130, 90, 148, 28, 76, 130, 5, 97, 241, 131, 35, 254, 4, 40, 8, 128, 15, 8, 235, 207, 11, 88, 142, 233, 81, 112, 71, 24, 136, 215, 15, 190, 152, 67, 128, 224, 27, 22, 232, 195, 23, 180, 227, 98, 96, 11, 55, 17, 211, 31, 244, 49, 102, 160, 24, 29, 249, 201, 71, 80, 1, 131, 136, 16, 194, 30, 237, 197, 215, 91, 68, 76, 108, 145, 5, 18, 27, 233, 119, 80, 5, 133, 0, 66, 65, 132, 32, 73, 48, 16, 13, 87, 112, 20, 133, 19, 28, 85, 113, 195, 1, 23, 48, 164, 85, 68, 18, 148, 24, 16, 0, 59)
$ico = New-Object IO.MemoryStream($WindowIcon, 0, $WindowIcon.Length)
$objForm.Icon = [System.Drawing.Icon]::FromHandle((new-object System.Drawing.Bitmap -argument $ico).GetHIcon())
$objForm.KeyPreview = $True
$objForm.TabStop = $false
$objForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedSingle


$MyLinkLabel = New-Object System.Windows.Forms.LinkLabel
$MyLinkLabel.Location = New-Object System.Drawing.Size(275,305)
$MyLinkLabel.Size = New-Object System.Drawing.Size(130,15)
$MyLinkLabel.DisabledLinkColor = [System.Drawing.Color]::Red
$MyLinkLabel.VisitedLinkColor = [System.Drawing.Color]::Blue
$MyLinkLabel.LinkBehavior = [System.Windows.Forms.LinkBehavior]::HoverUnderline
$MyLinkLabel.LinkColor = [System.Drawing.Color]::Navy
$MyLinkLabel.TabStop = $false
$MyLinkLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
$MyLinkLabel.Text = "www.myteamslab.com"
$MyLinkLabel.add_click(
{
	 [system.Diagnostics.Process]::start("https://www.myteamslab.com")
})
$objForm.Controls.Add($MyLinkLabel)


$DiscoverRangeLabel = New-Object System.Windows.Forms.Label
$DiscoverRangeLabel.Location = New-Object System.Drawing.Size(15,10) 
$DiscoverRangeLabel.Size = New-Object System.Drawing.Size(63,15) 
$DiscoverRangeLabel.Text = "IP / Range:"
$DiscoverRangeLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$DiscoverRangeLabel.TabStop = $False
$objForm.Controls.Add($DiscoverRangeLabel)


#Discover Range Text box ============================================================
$DiscoverRangeTextBox = New-Object System.Windows.Forms.TextBox
$DiscoverRangeTextBox.location = new-object system.drawing.size(80,10)
$DiscoverRangeTextBox.size= new-object system.drawing.size(215,23)
$DiscoverRangeTextBox.tabIndex = 1
$DiscoverRangeTextBox.text = "10.0.0.238"   
$DiscoverRangeTextBox.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$objform.controls.add($DiscoverRangeTextBox)
$DiscoverRangeTextBox.add_KeyUp(
{
	if ($_.KeyCode -eq "Enter") 
	{	
		if($DiscoverRangeTextBox.Text -ne "")
		{
			if($DiscoverRangeTextBox.Text -match ".*,.*")
			{
				$Sections = $DiscoverRangeTextBox.Text -split ","
				
				foreach($Section in $Sections)
				{
					[void] $DiscoverRangeListbox.Items.Add($Section)
				}
			}
			else
			{
				[void] $DiscoverRangeListbox.Items.Add($DiscoverRangeTextBox.Text)
			}
		}
	}
})


$DiscoverRangeListLabel = New-Object System.Windows.Forms.Label
$DiscoverRangeListLabel.Location = New-Object System.Drawing.Size(15,35) 
$DiscoverRangeListLabel.Size = New-Object System.Drawing.Size(63,15) 
$DiscoverRangeListLabel.Text = "IP List:"
$DiscoverRangeListLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$DiscoverRangeListLabel.TabStop = $False
$objForm.Controls.Add($DiscoverRangeListLabel)

# Add the listbox of ranges ============================================================
$DiscoverRangeListbox = New-Object System.Windows.Forms.Listbox 
$DiscoverRangeListbox.Location = New-Object System.Drawing.Size(80,35) 
$DiscoverRangeListbox.Size = New-Object System.Drawing.Size(215,60) 
$DiscoverRangeListbox.Sorted = $true
$DiscoverRangeListbox.TabStop = $false
$DiscoverRangeListbox.tabIndex = 3
$DiscoverRangeListbox.SelectionMode = "MultiExtended"
$DiscoverRangeListbox.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$objform.controls.add($DiscoverRangeListbox)
foreach($IPRange in $IPRanges)
{
	[void] $DiscoverRangeListbox.Items.Add($IPRange)
}

#Add button
$IPRangeAddButton = New-Object System.Windows.Forms.Button
$IPRangeAddButton.Location = New-Object System.Drawing.Size(300,10)
$IPRangeAddButton.Size = New-Object System.Drawing.Size(40,18)
$IPRangeAddButton.Text = "Add"
$IPRangeAddButton.tabIndex = 2
$IPRangeAddButton.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$IPRangeAddButton.Add_Click(
{
	if($DiscoverRangeTextBox.Text -ne "")
	{
		if($DiscoverRangeTextBox.Text -match ".*,.*")
		{
			$Sections = $DiscoverRangeTextBox.Text -split ","
			
			foreach($Section in $Sections)
			{
				[void] $DiscoverRangeListbox.Items.Add($Section)
			}
		}
		else
		{
			[void] $DiscoverRangeListbox.Items.Add($DiscoverRangeTextBox.Text)
		}
	}
})
$objForm.Controls.Add($IPRangeAddButton)


#Import button
$ImportButton = New-Object System.Windows.Forms.Button
$ImportButton.Location = New-Object System.Drawing.Size(345,10)
$ImportButton.Size = New-Object System.Drawing.Size(50,18)
$ImportButton.Text = "Import"
$ImportButton.tabIndex = 4
$ImportButton.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$ImportButton.Add_Click(
{
	#File Dialog
	[string] $pathVar = $pathbox.Text
	$Filter="All Files (*.*)|*.*"
	[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
	$objDialog = New-Object System.Windows.Forms.OpenFileDialog
	$objDialog.InitialDirectory = 
	$objDialog.FileName = "VVXIPAddresses.csv"
	$objDialog.Filter = $Filter
	$objDialog.Title = "Select File Name"
	$objDialog.CheckFileExists = $false
	$Show = $objDialog.ShowDialog()
	if ($Show -eq "OK")
	{
		[string]$content = ""
		[string] $filename = $objDialog.FileName
		$UserRecords = Import-Csv $filename
				
		foreach($UserRecord in $UserRecords)
		{
			$ClientIP = $UserRecord."IPAddress"
			
			if($ClientIP -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
			{
				[void] $DiscoverRangeListbox.Items.Add($ClientIP)
			}
		}
	}
	else
	{
		Write-Host "INFO: Canceled Import." -foreground "Yellow"
	}
})
$objForm.Controls.Add($ImportButton)


#Remove button
$IPRangeRemoveButton = New-Object System.Windows.Forms.Button
$IPRangeRemoveButton.Location = New-Object System.Drawing.Size(300,35)
$IPRangeRemoveButton.Size = New-Object System.Drawing.Size(40,18)
$IPRangeRemoveButton.Text = "Del"
$IPRangeRemoveButton.tabIndex = 5
$IPRangeRemoveButton.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$IPRangeRemoveButton.Add_Click(
{
	$beforeDelete = $DiscoverRangeListbox.SelectedIndex
	while($DiscoverRangeListbox.SelectedItems.Count -ne 0)
    {
        [void]$DiscoverRangeListbox.Items.Remove($DiscoverRangeListbox.SelectedItems[0])
    }
	if($beforeDelete -gt $DiscoverRangeListbox.SelectedItems.Count)
	{
		$beforeDelete = $beforeDelete - 1
	}
	if($DiscoverRangeListbox.items -gt 0)
	{
		$DiscoverRangeListbox.SelectedIndex = $beforeDelete
	}
	elseif($DiscoverRangeListbox.items -eq 0)
	{
		$DiscoverRangeListbox.SelectedIndex = 0
	}
})
$objForm.Controls.Add($IPRangeRemoveButton)

$Script:CancelScan = $false
#Remove button
$CancelScanButton = New-Object System.Windows.Forms.Button
$CancelScanButton.Location = New-Object System.Drawing.Size(300,60)
$CancelScanButton.Size = New-Object System.Drawing.Size(95,20)
$CancelScanButton.Text = "Cancel Action"
$CancelScanButton.forecolor = [System.Drawing.Color]::Red
#$CancelScanButton.tabIndex = 5
$CancelScanButton.TabStop = $false
$CancelScanButton.Visible = $false
$CancelScanButton.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$CancelScanButton.Add_Click(
{
	$Script:CancelScan = $true
})
$objForm.Controls.Add($CancelScanButton)



$RESTUsernameLabel = New-Object System.Windows.Forms.Label
$RESTUsernameLabel.Location = New-Object System.Drawing.Size(20,100) 
$RESTUsernameLabel.Size = New-Object System.Drawing.Size(105,20)
$RESTUsernameLabel.Text = "Device Username:"
$RESTUsernameLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$objForm.Controls.Add($RESTUsernameLabel) 

$RESTUsernameTextBox = new-object System.Windows.Forms.textbox
$RESTUsernameTextBox.location = new-object system.drawing.size(135,100)
$RESTUsernameTextBox.size = new-object system.drawing.size(160,15)
$RESTUsernameTextBox.text = $script:AdminUsername
$RESTUsernameTextBox.tabIndex = 6
$RESTUsernameTextBox.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$objForm.Controls.Add($RESTUsernameTextBox) 

$RESTPasswordLabel = New-Object System.Windows.Forms.Label
$RESTPasswordLabel.Location = New-Object System.Drawing.Size(20,125) 
$RESTPasswordLabel.Size = New-Object System.Drawing.Size(105,20)
$RESTPasswordLabel.Text = "Device Password:"
$RESTPasswordLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$objForm.Controls.Add($RESTPasswordLabel) 

$RESTPasswordTextBox = new-object System.Windows.Forms.textbox
$RESTPasswordTextBox.location = new-object system.drawing.size(135,125)
$RESTPasswordTextBox.size = new-object system.drawing.size(160,15)
$RESTPasswordTextBox.text = $script:AdminPassword   
$RESTPasswordTextBox.tabIndex = 7
$RESTPasswordTextBox.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$objForm.Controls.Add($RESTPasswordTextBox) 

$HTTPSLabel = New-Object System.Windows.Forms.Label
$HTTPSLabel.Location = New-Object System.Drawing.Size(20,150) 
$HTTPSLabel.Size = New-Object System.Drawing.Size(105,20)
$HTTPSLabel.Text = "HTTPS:"
$HTTPSLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$objForm.Controls.Add($HTTPSLabel) 

$HTTPSCheckBox = New-Object System.Windows.Forms.Checkbox 
$HTTPSCheckBox.Location = New-Object System.Drawing.Size(135,150) 
$HTTPSCheckBox.Size = New-Object System.Drawing.Size(20,20)
$HTTPSCheckBox.tabIndex = 8
$HTTPSCheckBox.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$HTTPSCheckBox.Add_Click(
{
	if($HTTPSCheckBox.Checked -eq $true)
	{
		$Script:UseHTTPS = $true
		if($PortTextBox.Text -eq "80")
		{
			$PortTextBox.Text = "443"
		}
	}
	else
	{
		$Script:UseHTTPS = $false
		if($PortTextBox.Text -eq "443")
		{
			$PortTextBox.Text = "80"
		}
	}
}
)
$objForm.Controls.Add($HTTPSCheckBox) 
$HTTPSCheckBox.Checked = $Script:UseHTTPS

$PortLabel = New-Object System.Windows.Forms.Label
$PortLabel.Location = New-Object System.Drawing.Size(20,175) 
$PortLabel.Size = New-Object System.Drawing.Size(105,20)
$PortLabel.Text = "Port Number:"
$PortLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$objForm.Controls.Add($PortLabel) 

$PortTextBox = new-object System.Windows.Forms.textbox
$PortTextBox.location = new-object system.drawing.size(135,175)
$PortTextBox.size = new-object system.drawing.size(160,15)
$PortTextBox.text = $Script:WebServicePort  
$PortTextBox.tabIndex = 9
$PortTextBox.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$objForm.Controls.Add($PortTextBox) 

#ProvisioningCombo box ============================================================
$ProvisioningCombo = New-Object System.Windows.Forms.ComboBox 
$ProvisioningCombo.Location = New-Object System.Drawing.Size(135,200) 
$ProvisioningCombo.Size = New-Object System.Drawing.Size(160,23) 
$ProvisioningCombo.DropDownHeight = 100 
$ProvisioningCombo.DropDownWidth = 160
$ProvisioningCombo.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$ProvisioningCombo.tabIndex = 10
$objForm.Controls.Add($ProvisioningCombo) 

[void] $ProvisioningCombo.Items.Add("Asia Pacific"); [void] $ProvisioningCombo.Items.Add("America"); [void] $ProvisioningCombo.Items.Add("Europe");
$ProvisioningArray = @("asia pacific", "america","europe")
#Leave default to asia pacific
#$index = $ProvisioningArray.ForEach{$_}.IndexOf($Script:Region.ToLower())

if($ProvisioningCombo.SelectedIndex  -gt 0)
{
	$Script:Region = $ProvisioningArray[$ProvisioningCombo.SelectedIndex]
}
else {
	$ProvisioningCombo.SelectedIndex = 0 #cosmetic only. line 333 variable holds default value.
}



$ProvisioningLabel = New-Object System.Windows.Forms.Label
$ProvisioningLabel.Location = New-Object System.Drawing.Size(20,200) 
$ProvisioningLabel.Size = New-Object System.Drawing.Size(105,20)
$ProvisioningLabel.Text = "Region:"
$ProvisioningLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$objForm.Controls.Add($ProvisioningLabel) 

# Create the Provision button.
$GetStatusButton = New-Object System.Windows.Forms.Button
$GetStatusButton.Location = New-Object System.Drawing.Size(30,240)
$GetStatusButton.Size = New-Object System.Drawing.Size(110,25)
$GetStatusButton.Text = "Get Teams Status"
$GetStatusButton.tabIndex = 11
$GetStatusButton.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$GetStatusButton.Add_Click({ 
    $StatusLabel.Text = "Status: Getting Status of devices..."
	[System.Windows.Forms.Application]::DoEvents()
	DisableButtons
	$IPRanges = @()
	if($DiscoverRangeListbox.Items.count -le 0)
	{
		if($DiscoverRangeTextBox.text -ne "" -and $DiscoverRangeTextBox.text -ne $null)
		{
			$IPRanges = @($DiscoverRangeTextBox.text)
		}
	}
	else
	{
		$IPRanges = $DiscoverRangeListbox.Items
	}
	
	$script:VVXIPAddress = $IPAddressTextBox.text
	$script:AdminUsername = $RESTUsernameTextBox.text
	$script:AdminPassword = $RESTPasswordTextBox.text
	$Script:WebServicePort = $PortTextBox.text
	$Script:UseHTTPS = $HTTPSCheckBox.Checked
	GetStatusPhones $IPRanges
	EnableButtons
	$StatusLabel.Text = ""
})
$objForm.Controls.Add($GetStatusButton)

# Create the Provision button.
$ProvisionButton = New-Object System.Windows.Forms.Button
$ProvisionButton.Location = New-Object System.Drawing.Size(30,270)
$ProvisionButton.Size = New-Object System.Drawing.Size(110,25)
$ProvisionButton.Text = "Intial Provisioning"
$ProvisionButton.tabIndex = 12
$ProvisionButton.Add_Click({ 
	$StatusLabel.Text = "Status: Provisioning devices..."
	[System.Windows.Forms.Application]::DoEvents()
	DisableButtons
	$IPRanges = @()
	if($DiscoverRangeListbox.Items.count -le 0)
	{
		if($DiscoverRangeTextBox.text -ne "" -and $DiscoverRangeTextBox.text -ne $null)
		{
			$IPRanges = @($DiscoverRangeTextBox.text)
		}
	}
	else
	{
		$IPRanges = $DiscoverRangeListbox.Items
	}
	
	$script:VVXIPAddress = $IPAddressTextBox.text
	$script:AdminUsername = $RESTUsernameTextBox.text
	$script:AdminPassword = $RESTPasswordTextBox.text
	$Script:WebServicePort = $PortTextBox.text
	$Script:UseHTTPS = $HTTPSCheckBox.Checked
	ProvisionPhones $IPRanges
	EnableButtons
	$StatusLabel.Text = ""
})
$objForm.Controls.Add($ProvisionButton) 

# Create the Provision button.
$SignInButton = New-Object System.Windows.Forms.Button
$SignInButton.Location = New-Object System.Drawing.Size(155,240)
$SignInButton.Size = New-Object System.Drawing.Size(110,25)
$SignInButton.Text = "Teams Sign In"
$SignInButton.tabIndex = 13
$SignInButton.Add_Click({ 
    $StatusLabel.Text = "Status: Signing in devices..."
	[System.Windows.Forms.Application]::DoEvents()
	DisableButtons
	$IPRanges = @()
	if($DiscoverRangeListbox.Items.count -le 0)
	{
		if($DiscoverRangeTextBox.text -ne "" -and $DiscoverRangeTextBox.text -ne $null)
		{
			$IPRanges = @($DiscoverRangeTextBox.text)
		}
	}
	else
	{
		$IPRanges = $DiscoverRangeListbox.Items
	}
	
	$script:VVXIPAddress = $IPAddressTextBox.text
	$script:AdminUsername = $RESTUsernameTextBox.text
	$script:AdminPassword = $RESTPasswordTextBox.text
	$Script:WebServicePort = $PortTextBox.text
	$Script:UseHTTPS = $HTTPSCheckBox.Checked
	SignInPhones $IPRanges
	EnableButtons
	$StatusLabel.Text = ""
})
$objForm.Controls.Add($SignInButton) 

# Create the Provision button.
$SignOutButton = New-Object System.Windows.Forms.Button
$SignOutButton.Location = New-Object System.Drawing.Size(155,270)
$SignOutButton.Size = New-Object System.Drawing.Size(110,25)
$SignOutButton.Text = "Teams Sign Out"
$SignOutButton.tabIndex = 14
$SignOutButton.Add_Click({
	$StatusLabel.Text = "Status: Signing out devices..."
	[System.Windows.Forms.Application]::DoEvents()	
	DisableButtons
	$IPRanges = @()
	if($DiscoverRangeListbox.Items.count -le 0)
	{
		if($DiscoverRangeTextBox.text -ne "" -and $DiscoverRangeTextBox.text -ne $null)
		{
			$IPRanges = @($DiscoverRangeTextBox.text)
		}
	}
	else
	{
		$IPRanges = $DiscoverRangeListbox.Items
	}
	
	$script:VVXIPAddress = $IPAddressTextBox.text
	$script:AdminUsername = $RESTUsernameTextBox.text
	$script:AdminPassword = $RESTPasswordTextBox.text
	$Script:WebServicePort = $PortTextBox.text
	$Script:UseHTTPS = $HTTPSCheckBox.Checked
	SignOutPhones $IPRanges
	EnableButtons
	$StatusLabel.Text = ""
})
$objForm.Controls.Add($SignOutButton) 

# Create the Change Password button.
$ChangePasswordButton = New-Object System.Windows.Forms.Button
$ChangePasswordButton.Location = New-Object System.Drawing.Size(280,240)
$ChangePasswordButton.Size = New-Object System.Drawing.Size(110,25)
$ChangePasswordButton.Text = "Change Password"
$ChangePasswordButton.tabIndex = 15
$ChangePasswordButton.Add_Click({ 
	$StatusLabel.Text = "Status: Changing Password..."
	[System.Windows.Forms.Application]::DoEvents()
	DisableButtons
	$IPRanges = @()
	if($DiscoverRangeListbox.Items.count -le 0)
	{
		if($DiscoverRangeTextBox.text -ne "" -and $DiscoverRangeTextBox.text -ne $null)
		{
			$IPRanges = @($DiscoverRangeTextBox.text)
		}
	}
	else
	{
		$IPRanges = $DiscoverRangeListbox.Items
	}
	
	$script:VVXIPAddress = $IPAddressTextBox.text
	$script:AdminUsername = $RESTUsernameTextBox.text
	$script:AdminPassword = $RESTPasswordTextBox.text
	$Script:WebServicePort = $PortTextBox.text
	$Script:UseHTTPS = $HTTPSCheckBox.Checked
	
	$NewPassword = ChangePasswordDialog
	if($NewPassword.GetType().Name -ne "Boolean")
	{
		ChangeDevicePassword $IPRanges $NewPassword
	}
	EnableButtons
	$StatusLabel.Text = ""
})
$objForm.Controls.Add($ChangePasswordButton) 


# Create the Restart button.
$RebootButton = New-Object System.Windows.Forms.Button
$RebootButton.Location = New-Object System.Drawing.Size(280,270)
$RebootButton.Size = New-Object System.Drawing.Size(110,25)
$RebootButton.Text = "Reboot"
$RebootButton.tabIndex = 16
$RebootButton.Add_Click({
	$StatusLabel.Text = "Status: Rebooting devices..."
	[System.Windows.Forms.Application]::DoEvents()
	DisableButtons
	$IPRanges = @()
	if($DiscoverRangeListbox.Items.count -le 0)
	{
		if($DiscoverRangeTextBox.text -ne "" -and $DiscoverRangeTextBox.text -ne $null)
		{
			$IPRanges = @($DiscoverRangeTextBox.text)
		}
	}
	else
	{
		$IPRanges = $DiscoverRangeListbox.Items
	}
	
	$script:VVXIPAddress = $IPAddressTextBox.text
	$script:AdminUsername = $RESTUsernameTextBox.text
	$script:AdminPassword = $RESTPasswordTextBox.text
	$Script:WebServicePort = $PortTextBox.text
	$Script:UseHTTPS = $HTTPSCheckBox.Checked
	RebootPhones $IPRanges
	EnableButtons
	$StatusLabel.Text = ""
})
$objForm.Controls.Add($RebootButton) 

	
# Add the Status Label ============================================================
$StatusLabel = New-Object System.Windows.Forms.Label
$StatusLabel.Location = New-Object System.Drawing.Size(10,308) 
$StatusLabel.Size = New-Object System.Drawing.Size(200,15) 
$StatusLabel.Text = ""
$StatusLabel.forecolor = [System.Drawing.Color]::Green
$StatusLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$StatusLabel.TabStop = $false
$objForm.Controls.Add($StatusLabel)
	

$ToolTip = New-Object System.Windows.Forms.ToolTip 
$ToolTip.BackColor = [System.Drawing.Color]::LightGoldenrodYellow 
$ToolTip.IsBalloon = $true 
$ToolTip.InitialDelay = 500 
$ToolTip.ReshowDelay = 500 
$ToolTip.AutoPopDelay = 10000
$ToolTip.SetToolTip($ImportButton, "This button will allow you to import a CSV file. Header format: `"IPAddress`"") 

function DisableButtons()
{
	$RebootButton.Enabled = $false
	$ChangePasswordButton.Enabled = $false
	$SignOutButton.Enabled = $false
	$SignInButton.Enabled = $false
	$ProvisionButton.Enabled = $false
	$GetStatusButton.Enabled = $false
	$CancelScanButton.Visible = $true
}

function EnableButtons()
{
	$RebootButton.Enabled = $true
	$ChangePasswordButton.Enabled = $true
	$SignOutButton.Enabled = $true
	$SignInButton.Enabled = $true
	$ProvisionButton.Enabled = $true
	$GetStatusButton.Enabled = $true
	$CancelScanButton.Visible = $false
}

function ResultsDialog([string] $results, [Array] $resultsObject)
{
	Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName System.Windows.Forms
	
	$SignInResultsLabel = New-Object System.Windows.Forms.Label
	$SignInResultsLabel.Location = New-Object System.Drawing.Size(20,15) 
	$SignInResultsLabel.Size = New-Object System.Drawing.Size(50,15) 
	$SignInResultsLabel.Text = "Results:"
	$SignInResultsLabel.TabStop = $False
	$SignInResultsLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
	
			
	#SignInResultsTextBox Text box ============================================================
	$SignInResultsTextBox = New-Object System.Windows.Forms.TextBox
	$SignInResultsTextBox.location = new-object system.drawing.size(20,40)
	$SignInResultsTextBox.size = new-object system.drawing.size(310,300)
	$SignInResultsTextBox.tabIndex = 3
	$SignInResultsTextBox.text = $results
	$SignInResultsTextBox.Multiline = $true
    $SignInResultsTextBox.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
    $SignInResultsTextBox.AcceptsReturn = $true
    $SignInResultsTextBox.AcceptsTab = $true
    $SignInResultsTextBox.WordWrap = $true
	$Font = New-Object System.Drawing.Font("Courier New",9,[System.Drawing.FontStyle]::Regular)
	$SignInResultsTextBox.Font = $Font 

    $SignInResultsTextBox.Anchor = [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Top
		
		
	# Create the OK button.
    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Size(120,350)
    $OKButton.Size = New-Object System.Drawing.Size(80,25)
    $OKButton.Text = "OK"
	#$okButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Left
	$OKButton.tabIndex = 1
    $OKButton.Add_Click({ 
	
		$form.Tag = $false
		$form.Close()
	})
	
	
	# Create the Export button.
    $ExportCSVButton = New-Object System.Windows.Forms.Button
    $ExportCSVButton.Location = New-Object System.Drawing.Size(230,10)
    $ExportCSVButton.Size = New-Object System.Drawing.Size(80,20)
    $ExportCSVButton.Text = "Export CSV"
	$ExportCSVButton.tabIndex = 2
    $ExportCSVButton.Add_Click({ 
	
		$filename = ""
		$csv = "`"IPAddress`",`"MACAddress`",`"Model`",`"Version`",`"Result`"`r`n"
		
		Write-Host "Exporting..." -foreground "yellow"
		[string] $pathVar = "c:\"
		$Filter="All Files (*.*)|*.*"
		[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
		$objDialog = New-Object System.Windows.Forms.SaveFileDialog
		#$objDialog.InitialDirectory = 
		$objDialog.FileName = "ResultOutput.csv"
		$objDialog.Filter = $Filter
		$objDialog.Title = "Export Results"
		$objDialog.CheckFileExists = $false
		$Show = $objDialog.ShowDialog()
		if ($Show -eq "OK")
		{
			[string] $filename = $objDialog.FileName
		}
		
		if($filename -ne "")
		{
			foreach($result in $resultsObject)
			{
				$csv += "`"" +[string]$result.IPAddress +"`",`""+ [string]$result.MACAddress + "`",`"" +[string]$result.Model +"`",`"" +[string]$result.Version +"`",`""+[string]$result.Result + "`"`r`n"
			}
			$csv | out-file -Encoding UTF8 -FilePath $filename -Force
			Write-Host "Completed Export." -foreground "yellow"
		}
		
	})


    # Create the form.
    $form = New-Object System.Windows.Forms.Form 
    $form.Text = "Results"
    $form.Size = New-Object System.Drawing.Size(360,430)
    $form.MinimumSize = New-Object System.Drawing.Size(360,200) 
	#$form.FormBorderStyle = 'FixedSingle'
    $form.StartPosition = "CenterScreen"
    $form.AutoSizeMode = 'GrowAndShrink'
	[byte[]]$WindowIcon = @(71, 73, 70, 56, 57, 97, 32, 0, 32, 0, 231, 137, 0, 0, 52, 93, 0, 52, 94, 0, 52, 95, 0, 53, 93, 0, 53, 94, 0, 53, 95, 0,53, 96, 0, 54, 94, 0, 54, 95, 0, 54, 96, 2, 54, 95, 0, 55, 95, 1, 55, 96, 1, 55, 97, 6, 55, 96, 3, 56, 98, 7, 55, 96, 8, 55, 97, 9, 56, 102, 15, 57, 98, 17, 58, 98, 27, 61, 99, 27, 61, 100, 24, 61, 116, 32, 63, 100, 36, 65, 102, 37, 66, 103, 41, 68, 104, 48, 72, 106, 52, 75, 108, 55, 77, 108, 57, 78, 109, 58, 79, 111, 59, 79, 110, 64, 83, 114, 65, 83, 114, 68, 85, 116, 69, 86, 117, 71, 88, 116, 75, 91, 120, 81, 95, 123, 86, 99, 126, 88, 101, 125, 89, 102, 126, 90, 103, 129, 92, 103, 130, 95, 107, 132, 97, 108, 132, 99, 110, 134, 100, 111, 135, 102, 113, 136, 104, 114, 137, 106, 116, 137, 106,116, 139, 107, 116, 139, 110, 119, 139, 112, 121, 143, 116, 124, 145, 120, 128, 147, 121, 129, 148, 124, 132, 150, 125,133, 151, 126, 134, 152, 127, 134, 152, 128, 135, 152, 130, 137, 154, 131, 138, 155, 133, 140, 157, 134, 141, 158, 135,141, 158, 140, 146, 161, 143, 149, 164, 147, 152, 167, 148, 153, 168, 151, 156, 171, 153, 158, 172, 153, 158, 173, 156,160, 174, 156, 161, 174, 158, 163, 176, 159, 163, 176, 160, 165, 177, 163, 167, 180, 166, 170, 182, 170, 174, 186, 171,175, 186, 173, 176, 187, 173, 177, 187, 174, 178, 189, 176, 180, 190, 177, 181, 191, 179, 182, 192, 180, 183, 193, 182,185, 196, 185, 188, 197, 188, 191, 200, 190, 193, 201, 193, 195, 203, 193, 196, 204, 196, 198, 206, 196, 199, 207, 197,200, 207, 197, 200, 208, 198, 200, 208, 199, 201, 208, 199, 201, 209, 200, 202, 209, 200, 202, 210, 202, 204, 212, 204,206, 214, 206, 208, 215, 206, 208, 216, 208, 210, 218, 209, 210, 217, 209, 210, 220, 209, 211, 218, 210, 211, 219, 210,211, 220, 210, 212, 219, 211, 212, 219, 211, 212, 220, 212, 213, 221, 214, 215, 223, 215, 216, 223, 215, 216, 224, 216,217, 224, 217, 218, 225, 218, 219, 226, 218, 220, 226, 219, 220, 226, 219, 220, 227, 220, 221, 227, 221, 223, 228, 224,225, 231, 228, 229, 234, 230, 231, 235, 251, 251, 252, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 33, 254, 17, 67, 114, 101, 97, 116, 101, 100, 32, 119, 105, 116, 104, 32, 71, 73, 77, 80, 0, 33, 249, 4, 1, 10, 0, 255, 0, 44, 0, 0, 0, 0, 32, 0, 32, 0, 0, 8, 254, 0, 255, 29, 24, 72, 176, 160, 193, 131, 8, 25, 60, 16, 120, 192, 195, 10, 132, 16, 35, 170, 248, 112, 160, 193, 64, 30, 135, 4, 68, 220, 72, 16, 128, 33, 32, 7, 22, 92, 68, 84, 132, 35, 71, 33, 136, 64, 18, 228, 81, 135, 206, 0, 147, 16, 7, 192, 145, 163, 242, 226, 26, 52, 53, 96, 34, 148, 161, 230, 76, 205, 3, 60, 214, 204, 72, 163, 243, 160, 25, 27, 62, 11, 6, 61, 96, 231, 68, 81, 130, 38, 240, 28, 72, 186, 114, 205, 129, 33, 94, 158, 14, 236, 66, 100, 234, 207, 165, 14, 254, 108, 120, 170, 193, 15, 4, 175, 74, 173, 30, 120, 50, 229, 169, 20, 40, 3, 169, 218, 28, 152, 33, 80, 2, 157, 6, 252, 100, 136, 251, 85, 237, 1, 46, 71,116, 26, 225, 66, 80, 46, 80, 191, 37, 244, 0, 48, 57, 32, 15, 137, 194, 125, 11, 150, 201, 97, 18, 7, 153, 130, 134, 151, 18, 140, 209, 198, 36, 27, 24, 152, 35, 23, 188, 147, 98, 35, 138, 56, 6, 51, 251, 29, 24, 4, 204, 198, 47, 63, 82, 139, 38, 168, 64, 80, 7, 136, 28, 250, 32, 144, 157, 246, 96, 19, 43, 16, 169, 44, 57, 168, 250, 32, 6, 66, 19, 14, 70, 248, 99, 129, 248, 236, 130, 90, 148, 28, 76, 130, 5, 97, 241, 131, 35, 254, 4, 40, 8, 128, 15, 8, 235, 207, 11, 88, 142, 233, 81, 112, 71, 24, 136, 215, 15, 190, 152, 67, 128, 224, 27, 22, 232, 195, 23, 180, 227, 98, 96, 11, 55, 17, 211, 31, 244, 49, 102, 160, 24, 29, 249, 201, 71, 80, 1, 131, 136, 16, 194, 30, 237, 197, 215, 91, 68, 76, 108, 145, 5, 18, 27, 233, 119, 80, 5, 133, 0, 66, 65, 132, 32, 73, 48, 16, 13, 87, 112, 20, 133, 19, 28, 85, 113, 195, 1, 23, 48, 164, 85, 68, 18, 148, 24, 16, 0, 59)
	$ico = New-Object IO.MemoryStream($WindowIcon, 0, $WindowIcon.Length)
	$form.Icon = [System.Drawing.Icon]::FromHandle((new-object System.Drawing.Bitmap -argument $ico).GetHIcon())
	$form.Topmost = $True
    $form.AcceptButton = $OKButton
    $form.ShowInTaskbar = $true
	$form.MinimizeBox = $False
    $form.Tag = $false
	
	$form.Controls.Add($SignInResultsLabel)
	$form.Controls.Add($SignInResultsTextBox)
	$form.Controls.Add($OKButton)
	$form.Controls.Add($ExportCSVButton)
	
	$form.Add_Resize({ 
		$OKButton.Location = New-Object System.Drawing.Size((($form.Width / 2) - 55),($form.Height - 80))
		$ExportCSVButton.Location = New-Object System.Drawing.Size(($form.Width - 130),10)
	})
	
			
    # Initialize and show the form.
    $form.Add_Shown({$form.Activate()})
    $form.ShowDialog() > $null 
     
	return $form.Tag
}

function ChangePasswordDialog()
{
	
	Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName System.Windows.Forms
	
	$NewPasswordLabel = New-Object System.Windows.Forms.Label
	$NewPasswordLabel.Location = New-Object System.Drawing.Size(20,20) 
	$NewPasswordLabel.Size = New-Object System.Drawing.Size(200,15) 
	$NewPasswordLabel.Text = "New Password:"
	$NewPasswordLabel.TabStop = $False
	$NewPasswordLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
	
	
	#NewPasswordTextBox Text box ============================================================
	$NewPasswordTextBox = New-Object System.Windows.Forms.TextBox
	$NewPasswordTextBox.location = new-object system.drawing.size(20,40)
	$NewPasswordTextBox.size = new-object system.drawing.size(250,20)
	$NewPasswordTextBox.tabIndex = 1
	$NewPasswordTextBox.text = $script:NewPassword
    $NewPasswordTextBox.Anchor = [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Bottom
		
		
	# Create the OK button.
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Size(60,80)
    $okButton.Size = New-Object System.Drawing.Size(75,25)
    $okButton.Text = "OK"
	$okButton.tabIndex = 2
    $okButton.Add_Click({ 

		$form.Tag = $NewPasswordTextBox.text
		$form.Close()
	})
	
	# Create the Cancel Button.
    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Size(150,80)
    $CancelButton.Size = New-Object System.Drawing.Size(75,25)
    $CancelButton.Text = "Cancel"
	$CancelButton.tabIndex = 3
    $CancelButton.Add_Click({ 
	
		$form.Tag = $false
		$form.Close()
	})


    # Create the form.
    $form = New-Object System.Windows.Forms.Form 
    $form.Text = "Change Password"
    $form.Size = New-Object System.Drawing.Size(300,160)
    $form.FormBorderStyle = 'FixedSingle'
    $form.StartPosition = "CenterScreen"
    $form.AutoSizeMode = 'GrowAndShrink'
	[byte[]]$WindowIcon = @(71, 73, 70, 56, 57, 97, 32, 0, 32, 0, 231, 137, 0, 0, 52, 93, 0, 52, 94, 0, 52, 95, 0, 53, 93, 0, 53, 94, 0, 53, 95, 0,53, 96, 0, 54, 94, 0, 54, 95, 0, 54, 96, 2, 54, 95, 0, 55, 95, 1, 55, 96, 1, 55, 97, 6, 55, 96, 3, 56, 98, 7, 55, 96, 8, 55, 97, 9, 56, 102, 15, 57, 98, 17, 58, 98, 27, 61, 99, 27, 61, 100, 24, 61, 116, 32, 63, 100, 36, 65, 102, 37, 66, 103, 41, 68, 104, 48, 72, 106, 52, 75, 108, 55, 77, 108, 57, 78, 109, 58, 79, 111, 59, 79, 110, 64, 83, 114, 65, 83, 114, 68, 85, 116, 69, 86, 117, 71, 88, 116, 75, 91, 120, 81, 95, 123, 86, 99, 126, 88, 101, 125, 89, 102, 126, 90, 103, 129, 92, 103, 130, 95, 107, 132, 97, 108, 132, 99, 110, 134, 100, 111, 135, 102, 113, 136, 104, 114, 137, 106, 116, 137, 106,116, 139, 107, 116, 139, 110, 119, 139, 112, 121, 143, 116, 124, 145, 120, 128, 147, 121, 129, 148, 124, 132, 150, 125,133, 151, 126, 134, 152, 127, 134, 152, 128, 135, 152, 130, 137, 154, 131, 138, 155, 133, 140, 157, 134, 141, 158, 135,141, 158, 140, 146, 161, 143, 149, 164, 147, 152, 167, 148, 153, 168, 151, 156, 171, 153, 158, 172, 153, 158, 173, 156,160, 174, 156, 161, 174, 158, 163, 176, 159, 163, 176, 160, 165, 177, 163, 167, 180, 166, 170, 182, 170, 174, 186, 171,175, 186, 173, 176, 187, 173, 177, 187, 174, 178, 189, 176, 180, 190, 177, 181, 191, 179, 182, 192, 180, 183, 193, 182,185, 196, 185, 188, 197, 188, 191, 200, 190, 193, 201, 193, 195, 203, 193, 196, 204, 196, 198, 206, 196, 199, 207, 197,200, 207, 197, 200, 208, 198, 200, 208, 199, 201, 208, 199, 201, 209, 200, 202, 209, 200, 202, 210, 202, 204, 212, 204,206, 214, 206, 208, 215, 206, 208, 216, 208, 210, 218, 209, 210, 217, 209, 210, 220, 209, 211, 218, 210, 211, 219, 210,211, 220, 210, 212, 219, 211, 212, 219, 211, 212, 220, 212, 213, 221, 214, 215, 223, 215, 216, 223, 215, 216, 224, 216,217, 224, 217, 218, 225, 218, 219, 226, 218, 220, 226, 219, 220, 226, 219, 220, 227, 220, 221, 227, 221, 223, 228, 224,225, 231, 228, 229, 234, 230, 231, 235, 251, 251, 252, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,255, 255, 255, 255, 255, 255, 255, 255, 33, 254, 17, 67, 114, 101, 97, 116, 101, 100, 32, 119, 105, 116, 104, 32, 71, 73, 77, 80, 0, 33, 249, 4, 1, 10, 0, 255, 0, 44, 0, 0, 0, 0, 32, 0, 32, 0, 0, 8, 254, 0, 255, 29, 24, 72, 176, 160, 193, 131, 8, 25, 60, 16, 120, 192, 195, 10, 132, 16, 35, 170, 248, 112, 160, 193, 64, 30, 135, 4, 68, 220, 72, 16, 128, 33, 32, 7, 22, 92, 68, 84, 132, 35, 71, 33, 136, 64, 18, 228, 81, 135, 206, 0, 147, 16, 7, 192, 145, 163, 242, 226, 26, 52, 53, 96, 34, 148, 161, 230, 76, 205, 3, 60, 214, 204, 72, 163, 243, 160, 25, 27, 62, 11, 6, 61, 96, 231, 68, 81, 130, 38, 240, 28, 72, 186, 114, 205, 129, 33, 94, 158, 14, 236, 66, 100, 234, 207, 165, 14, 254, 108, 120, 170, 193, 15, 4, 175, 74, 173, 30, 120, 50, 229, 169, 20, 40, 3, 169, 218, 28, 152, 33, 80, 2, 157, 6, 252, 100, 136, 251, 85, 237, 1, 46, 71,116, 26, 225, 66, 80, 46, 80, 191, 37, 244, 0, 48, 57, 32, 15, 137, 194, 125, 11, 150, 201, 97, 18, 7, 153, 130, 134, 151, 18, 140, 209, 198, 36, 27, 24, 152, 35, 23, 188, 147, 98, 35, 138, 56, 6, 51, 251, 29, 24, 4, 204, 198, 47, 63, 82, 139, 38, 168, 64, 80, 7, 136, 28, 250, 32, 144, 157, 246, 96, 19, 43, 16, 169, 44, 57, 168, 250, 32, 6, 66, 19, 14, 70, 248, 99, 129, 248, 236, 130, 90, 148, 28, 76, 130, 5, 97, 241, 131, 35, 254, 4, 40, 8, 128, 15, 8, 235, 207, 11, 88, 142, 233, 81, 112, 71, 24, 136, 215, 15, 190, 152, 67, 128, 224, 27, 22, 232, 195, 23, 180, 227, 98, 96, 11, 55, 17, 211, 31, 244, 49, 102, 160, 24, 29, 249, 201, 71, 80, 1, 131, 136, 16, 194, 30, 237, 197, 215, 91, 68, 76, 108, 145, 5, 18, 27, 233, 119, 80, 5, 133, 0, 66, 65, 132, 32, 73, 48, 16, 13, 87, 112, 20, 133, 19, 28, 85, 113, 195, 1, 23, 48, 164, 85, 68, 18, 148, 24, 16, 0, 59)
	$ico = New-Object IO.MemoryStream($WindowIcon, 0, $WindowIcon.Length)
	$form.Icon = [System.Drawing.Icon]::FromHandle((new-object System.Drawing.Bitmap -argument $ico).GetHIcon())
	$form.Topmost = $True
    $form.AcceptButton = $okButton
    $form.ShowInTaskbar = $true
	$form.MinimizeBox = $False
	$form.MaximizeBox = $False
    $form.Tag = $false
	
	$form.Controls.Add($NewPasswordLabel)
	$form.Controls.Add($NewPasswordTextBox)
	$form.Controls.Add($okButton)
	$form.Controls.Add($CancelButton)
		
    # Initialize and show the form.
    $form.Add_Shown({$form.Activate()})
    $form.ShowDialog() > $null
     
	return $form.Tag
}
} #LOAD UI END

function ChangeDevicePassword([Array] $IPRanges, [string]$NewPassword)
{
	$resultObjectArray = @()
	foreach($IPRange in $IPRanges)
	{
		
		[string]$IPRange = $IPRange
		
		[string]$StartTemp = ""
		[string]$EndTemp = ""
		$UserIPAddressArray = @()
		
		if($IPRange -match "^(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])$") #SINGLE IP
		{
			[String[]]$UserIPAddressArray += $IPRange
		}
		if($IPRange.Contains("/")) #PROCESS A SUBNET STRING
		{
			$IPRangeSplit = $IPRange -split "/"
			[string]$Network = $IPRangeSplit[0]
			if($Network -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
			{
				[string]$Mask = $IPRangeSplit[1]
				
				if($Mask -match "^([0-9]|[1-2][0-9]|30)$")
				{
					
					[Net.IPAddress]$NetworkIPAddress = [System.Net.IPAddress]::Parse($Network)
					[int]$MaskNumber = [int]::Parse($Mask)
					
					[UInt32] $DecimalMaskIP = [Convert]::ToUInt32($(("1" * $MaskNumber).PadRight(32, "0")), 2)
					
					$i = 3; $DecimalNetworkIP = 0;
					$NetworkIPAddress.GetAddressBytes() | ForEach-Object { [UInt32]$DecimalNetworkIP += $_ * [Math]::Pow(256, $i); $i-- }
									
					[UInt32] $NetworkAddressInt = $DecimalNetworkIP -band $DecimalMaskIP
					[UInt32]$InvertedMask = $DecimalMaskIP -bxor 0xFFFFFFFF
					[UInt32] $BroadcastInt = $DecimalNetworkIP -bor $InvertedMask
					
					$StartTempInt = $NetworkAddressInt + 1
					
					$DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
					$Remainder = $StartTempInt % [Math]::Pow(256, $i)
					($StartTempInt - $Remainder) / [Math]::Pow(256, $i)
					$StartTempInt = $Remainder
					} )
					#Start Address
					[string]$StartTemp = [String]::Join('.', $DottedIP)
					
					$EndTempInt = $BroadcastInt - 1
					$DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
					$Remainder = $EndTempInt % [Math]::Pow(256, $i)
					($EndTempInt - $Remainder) / [Math]::Pow(256, $i)
					$EndTempInt = $Remainder
					} )
					#End Address			
					[string]$EndTemp = [String]::Join('.', $DottedIP)
					
				}
				else
				{
					Write-Host "ERROR: Bad subnet mask." -foreground "red"
				}
			}
			else
			{
				Write-Host "ERROR: Bad network address." -foreground
			}

		}
		else #PROCESS A RANGE STRING
		{
			$IPRangeSplit = $IPRange -split "-"
			[string]$StartTemp = $IPRangeSplit[0]
			[string]$EndTemp = $IPRangeSplit[1]
		}
		#Check IP Addresses
		if($StartTemp -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
		{
			[string]$StartIP = $StartTemp
		}
		else
		{
			[string]$StartIP = ""
		}
		if($EndTemp -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
		{
			[string]$EndIP = $EndTemp
		}
		else
		{
			[string]$EndIP = ""
		}
			
		if($StartIP -ne "" -and $EndIP -ne "")
		{	
			Write-Host ""
			Write-Host "-----------------------------------------------------------------------------------------" -foreground "Green"
			Write-Host "Password Change Range of IP Addresses $StartIP to $EndIP. Starting Scan!" -foreground "Green"
			Write-Host "-----------------------------------------------------------------------------------------" -foreground "Green"

			# Get Start Time
			$startDTMScan = (Get-Date)
				
			[int]$FirstOctet,[int]$SecondOctet,[int]$ThirdOctet,[int]$FourthOctet = $StartIP.split('.')
			[int]$FirstOctetEnd,[int]$SecondOctetEnd,[int]$ThirdOctetEnd,[int]$FourthOctetEnd = $EndIP.split('.')
				
			$FinalAddressOct1 = ""
			$FinalAddressOct2 = ""
			$FinalAddressOct3 = ""
			$FinalAddressOct4 = ""
													
			foreach ($i in ($FirstOctet..$FirstOctetEnd))
			{
				$FinalAddressOct1 = "${i}."
				foreach ($j in ($SecondOctet..$SecondOctetEnd))
				{
					$FinalAddressOct2 = "${FinalAddressOct1}${j}."
					
					foreach ($k in ($ThirdOctet..$ThirdOctetEnd))
					{
						$FinalAddressOct3 = "${FinalAddressOct2}${k}."
					
						foreach ($l in ($FourthOctet..$FourthOctetEnd))
						{
							$FinalAddressOct4 = "${FinalAddressOct3}${l}"
							[string]$ClientIP = $FinalAddressOct4
							[String[]]$UserIPAddressArray += $ClientIP
						}
					}
				}
			}
		}

		# Get Start Time
		$startDTM = (Get-Date)
				
		Write-Host "Starting Provisioning..." -foreground "green"
		foreach($IPAddress in $UserIPAddressArray)
		{
			if($Script:CancelScan)
			{break}
			
			$ClientIP = $IPAddress
			$ClientPort = $Script:WebServicePort
			$username = $script:AdminUsername
			$password = $script:AdminPassword 
			$UseHTTPS = $Script:UseHTTPS
			
			Write-Verbose "PasswordChange: $NewPassword" 
			$resultObjectArray += PasswordChange $ClientIP $ClientPort $username $password $UseHTTPS $NewPassword	
			[System.Windows.Forms.Application]::DoEvents()			
		}
		$Script:CancelScan = $false
	
		# Get End Time
		$endDTM = (Get-Date)
		# Echo Time elapsed
		Write-Host "Elapsed Time: $(($endDTM-$startDTM).totalseconds) seconds" -foreground "green"
		Write-Host "-----------------------------------------------------------------------------------------" -foreground "green"
		
	}
		
	if($resultObjectArray -ne $null)
	{
		if($OpenUI) #LOAD UI START
		{
			$statusText = ""
			foreach($resultObject in $resultObjectArray)
			{
				$statusText += "----------------------------------------`r`n"
				$statusText += "IP Address: {0}`r`n" -f $resultObject.IPAddress
				if($resultObject.Model -ne ""){$statusText += "Model: {0}`r`n" -f $resultObject.Model}
				if($resultObject.MACAddress -ne ""){$statusText += "MAC Address: {0}`r`n" -f $resultObject.MACAddress}
				$statusText += "Result: {0}`r`n"  -f $resultObject.Result
				$statusText += "----------------------------------------`r`n"
			}
			ResultsDialog $statusText $resultObjectArray
		}
		else
		{
			return $resultObjectArray
		}
		
	}
}



function ProvisionPhones([Array] $IPRanges)
{
	$resultObjectArray = @()
	foreach($IPRange in $IPRanges)
	{
		
		[string]$IPRange = $IPRange
		
		[string]$StartTemp = ""
		[string]$EndTemp = ""
		$UserIPAddressArray = @()
		
		if($IPRange -match "^(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])$") #SINGLE IP
		{
			[String[]]$UserIPAddressArray += $IPRange
		}
		if($IPRange.Contains("/")) #PROCESS A SUBNET STRING
		{
			$IPRangeSplit = $IPRange -split "/"
			[string]$Network = $IPRangeSplit[0]
			if($Network -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
			{
				[string]$Mask = $IPRangeSplit[1]
				
				if($Mask -match "^([0-9]|[1-2][0-9]|30)$")
				{
					
					[Net.IPAddress]$NetworkIPAddress = [System.Net.IPAddress]::Parse($Network)
					[int]$MaskNumber = [int]::Parse($Mask)
					
					[UInt32] $DecimalMaskIP = [Convert]::ToUInt32($(("1" * $MaskNumber).PadRight(32, "0")), 2)
					
					$i = 3; $DecimalNetworkIP = 0;
					$NetworkIPAddress.GetAddressBytes() | ForEach-Object { [UInt32]$DecimalNetworkIP += $_ * [Math]::Pow(256, $i); $i-- }
									
					[UInt32] $NetworkAddressInt = $DecimalNetworkIP -band $DecimalMaskIP
					[UInt32]$InvertedMask = $DecimalMaskIP -bxor 0xFFFFFFFF
					[UInt32] $BroadcastInt = $DecimalNetworkIP -bor $InvertedMask
					
					$StartTempInt = $NetworkAddressInt + 1
					
					$DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
					$Remainder = $StartTempInt % [Math]::Pow(256, $i)
					($StartTempInt - $Remainder) / [Math]::Pow(256, $i)
					$StartTempInt = $Remainder
					} )
					#Start Address
					[string]$StartTemp = [String]::Join('.', $DottedIP)
					
					$EndTempInt = $BroadcastInt - 1
					$DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
					$Remainder = $EndTempInt % [Math]::Pow(256, $i)
					($EndTempInt - $Remainder) / [Math]::Pow(256, $i)
					$EndTempInt = $Remainder
					} )
					#End Address			
					[string]$EndTemp = [String]::Join('.', $DottedIP)
					
				}
				else
				{
					Write-Host "ERROR: Bad subnet mask." -foreground "red"
				}
			}
			else
			{
				Write-Host "ERROR: Bad network address." -foreground
			}

		}
		else #PROCESS A RANGE STRING
		{
			$IPRangeSplit = $IPRange -split "-"
			[string]$StartTemp = $IPRangeSplit[0]
			[string]$EndTemp = $IPRangeSplit[1]
		}
		#Check IP Addresses
		if($StartTemp -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
		{
			[string]$StartIP = $StartTemp
		}
		else
		{
			[string]$StartIP = ""
		}
		if($EndTemp -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
		{
			[string]$EndIP = $EndTemp
		}
		else
		{
			[string]$EndIP = ""
		}
			
		if($StartIP -ne "" -and $EndIP -ne "")
		{	
			Write-Host ""
			Write-Host "-----------------------------------------------------------------------------------------" -foreground "Green"
			Write-Host "Provisioning Range of IP Addresses $StartIP to $EndIP. Starting Scan!" -foreground "Green"
			Write-Host "-----------------------------------------------------------------------------------------" -foreground "Green"

			# Get Start Time
			$startDTMScan = (Get-Date)
				
			[int]$FirstOctet,[int]$SecondOctet,[int]$ThirdOctet,[int]$FourthOctet = $StartIP.split('.')
			[int]$FirstOctetEnd,[int]$SecondOctetEnd,[int]$ThirdOctetEnd,[int]$FourthOctetEnd = $EndIP.split('.')
				
			$FinalAddressOct1 = ""
			$FinalAddressOct2 = ""
			$FinalAddressOct3 = ""
			$FinalAddressOct4 = ""
			
			
			foreach ($i in ($FirstOctet..$FirstOctetEnd))
			{
				$FinalAddressOct1 = "${i}."
				foreach ($j in ($SecondOctet..$SecondOctetEnd))
				{
					$FinalAddressOct2 = "${FinalAddressOct1}${j}."
					
					foreach ($k in ($ThirdOctet..$ThirdOctetEnd))
					{
						$FinalAddressOct3 = "${FinalAddressOct2}${k}."
					
						foreach ($l in ($FourthOctet..$FourthOctetEnd))
						{
							$FinalAddressOct4 = "${FinalAddressOct3}${l}"
							[string]$ClientIP = $FinalAddressOct4
							[String[]]$UserIPAddressArray += $ClientIP
						}
					}
				}
			}
		}

		# Get Start Time
		$startDTM = (Get-Date)
				
		Write-Host "Starting Provisioning..." -foreground "green"
		foreach($IPAddress in $UserIPAddressArray)
		{
			if($Script:CancelScan)
			{break}
			
			$ClientIP = $IPAddress
			$ClientPort = $Script:WebServicePort
			$username = $script:AdminUsername
			$password = $script:AdminPassword 
			$UseHTTPS = $Script:UseHTTPS
			
			Write-Verbose "SetProvisioningServer: $ClientIP $ClientPort $username $password $UseHTTPS" 
			$resultObjectArray += SetProvisioningServer $ClientIP $ClientPort $username $password $UseHTTPS
			[System.Windows.Forms.Application]::DoEvents()	
		}
		$Script:CancelScan = $false
		
		# Get End Time
		$endDTM = (Get-Date)
		# Echo Time elapsed
		Write-Host "Elapsed Time: $(($endDTM-$startDTM).totalseconds) seconds" -foreground "green"
		Write-Host "-----------------------------------------------------------------------------------------" -foreground "green"
		
	
	}
	if($resultObjectArray -ne $null)
	{
		if($OpenUI) #LOAD UI START
		{
			$statusText = ""
			foreach($resultObject in $resultObjectArray)
			{
				$statusText += "----------------------------------------`r`n"
				$statusText += "IP Address: {0}`r`n" -f $resultObject.IPAddress
				if($resultObject.Model -ne ""){$statusText += "Model: {0}`r`n" -f $resultObject.Model}
				if($resultObject.MACAddress -ne ""){$statusText += "MAC Address: {0}`r`n" -f $resultObject.MACAddress}
				$statusText += "Result: {0}`r`n"  -f $resultObject.Result
				$statusText += "----------------------------------------`r`n"
			}
			ResultsDialog $statusText $resultObjectArray
		}
		else
		{
			return $resultObjectArray
		}
		
	}
}


function SignInPhones([Array]$IPRanges)
{
	$resultObjectArray = @()
	foreach($IPRange in $IPRanges)
	{
		
		[string]$IPRange = $IPRange
		
		[string]$StartTemp = ""
		[string]$EndTemp = ""
		$UserIPAddressArray = @()
		
		if($IPRange -match "^(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])$") #SINGLE IP
		{
			[String[]]$UserIPAddressArray += $IPRange
		}
		if($IPRange.Contains("/")) #PROCESS A SUBNET STRING
		{
			$IPRangeSplit = $IPRange -split "/"
			[string]$Network = $IPRangeSplit[0]
			if($Network -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
			{
				[string]$Mask = $IPRangeSplit[1]
				
				if($Mask -match "^([0-9]|[1-2][0-9]|30)$")
				{
					
					[Net.IPAddress]$NetworkIPAddress = [System.Net.IPAddress]::Parse($Network)
					[int]$MaskNumber = [int]::Parse($Mask)
					
					[UInt32] $DecimalMaskIP = [Convert]::ToUInt32($(("1" * $MaskNumber).PadRight(32, "0")), 2)
					
					$i = 3; $DecimalNetworkIP = 0;
					$NetworkIPAddress.GetAddressBytes() | ForEach-Object { [UInt32]$DecimalNetworkIP += $_ * [Math]::Pow(256, $i); $i-- }
									
					[UInt32] $NetworkAddressInt = $DecimalNetworkIP -band $DecimalMaskIP
					[UInt32]$InvertedMask = $DecimalMaskIP -bxor 0xFFFFFFFF
					[UInt32] $BroadcastInt = $DecimalNetworkIP -bor $InvertedMask
					
					$StartTempInt = $NetworkAddressInt + 1
					
					$DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
					$Remainder = $StartTempInt % [Math]::Pow(256, $i)
					($StartTempInt - $Remainder) / [Math]::Pow(256, $i)
					$StartTempInt = $Remainder
					} )
					#Start Address
					[string]$StartTemp = [String]::Join('.', $DottedIP)
					
					$EndTempInt = $BroadcastInt - 1
					$DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
					$Remainder = $EndTempInt % [Math]::Pow(256, $i)
					($EndTempInt - $Remainder) / [Math]::Pow(256, $i)
					$EndTempInt = $Remainder
					} )
					#End Address			
					[string]$EndTemp = [String]::Join('.', $DottedIP)
					
				}
				else
				{
					Write-Host "ERROR: Bad subnet mask." -foreground "red"
				}
			}
			else
			{
				Write-Host "ERROR: Bad network address." -foreground
			}

		}
		else #PROCESS A RANGE STRING
		{
			$IPRangeSplit = $IPRange -split "-"
			[string]$StartTemp = $IPRangeSplit[0]
			[string]$EndTemp = $IPRangeSplit[1]
		}
		#Check IP Addresses
		if($StartTemp -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
		{
			[string]$StartIP = $StartTemp
		}
		else
		{
			[string]$StartIP = ""
		}
		if($EndTemp -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
		{
			[string]$EndIP = $EndTemp
		}
		else
		{
			[string]$EndIP = ""
		}
			
		if($StartIP -ne "" -and $EndIP -ne "")
		{	
			Write-Host ""
			Write-Host "-----------------------------------------------------------------------------------------" -foreground "Green"
			Write-Host "Signing-in Range of IP Addresses $StartIP to $EndIP. Starting Scan!" -foreground "Green"
			Write-Host "-----------------------------------------------------------------------------------------" -foreground "Green"

			# Get Start Time
			$startDTMScan = (Get-Date)
				
			[int]$FirstOctet,[int]$SecondOctet,[int]$ThirdOctet,[int]$FourthOctet = $StartIP.split('.')
			[int]$FirstOctetEnd,[int]$SecondOctetEnd,[int]$ThirdOctetEnd,[int]$FourthOctetEnd = $EndIP.split('.')
				
			$FinalAddressOct1 = ""
			$FinalAddressOct2 = ""
			$FinalAddressOct3 = ""
			$FinalAddressOct4 = ""
			
			foreach ($i in ($FirstOctet..$FirstOctetEnd))
			{
				$FinalAddressOct1 = "${i}."
				foreach ($j in ($SecondOctet..$SecondOctetEnd))
				{
					$FinalAddressOct2 = "${FinalAddressOct1}${j}."
					
					foreach ($k in ($ThirdOctet..$ThirdOctetEnd))
					{
						$FinalAddressOct3 = "${FinalAddressOct2}${k}."
					
						foreach ($l in ($FourthOctet..$FourthOctetEnd))
						{
							$FinalAddressOct4 = "${FinalAddressOct3}${l}"
							[string]$ClientIP = $FinalAddressOct4
							[String[]]$UserIPAddressArray += $ClientIP
						}
					}
				}
			}
		}

		# Get Start Time
		$startDTM = (Get-Date)
				
		Write-Host "Starting Device Sign in..." -foreground "green"
		foreach($IPAddress in $UserIPAddressArray)
		{	
			if($Script:CancelScan)
			{break}
			
			$ClientIP = $IPAddress
			$ClientPort = $Script:WebServicePort
			$username = $script:AdminUsername
			$password = $script:AdminPassword 
			$UseHTTPS = $Script:UseHTTPS
			
			Write-Verbose "SignIn: $ClientIP $ClientPort $username $password $UseHTTPS" 
			$resultObjectArray += SignIn $ClientIP $ClientPort $username $password $UseHTTPS
			[System.Windows.Forms.Application]::DoEvents()	
		}
		$Script:CancelScan = $false
		
		# Get End Time
		$endDTM = (Get-Date)
		# Echo Time elapsed
		Write-Host "Elapsed Time: $(($endDTM-$startDTM).totalseconds) seconds" -foreground "green"
		Write-Host "-----------------------------------------------------------------------------------------" -foreground "green"
	
	}
	if($resultObjectArray -ne $null)
	{
		if($OpenUI) #LOAD UI START
		{
			$statusText = ""
			foreach($resultObject in $resultObjectArray)
			{
				$statusText += "----------------------------------------`r`n"
				$statusText += "IP Address: {0}`r`n" -f $resultObject.IPAddress
				if($resultObject.Model -ne ""){$statusText += "Model: {0}`r`n" -f $resultObject.Model}
				if($resultObject.MACAddress -ne ""){$statusText += "MAC Address: {0}`r`n" -f $resultObject.MACAddress}
				$statusText += "URL: {0}`r`n" -f $resultObject.URL
				$statusText += "Result: {0}`r`n"  -f $resultObject.Result
				$statusText += "----------------------------------------`r`n"
			}
			ResultsDialog $statusText $resultObjectArray
		}
		else
		{
			return $resultObjectArray
		}
		
	}
}



function SignOutPhones([Array] $IPRanges)
{
	$resultObjectArray = @()
	foreach($IPRange in $IPRanges)
	{
		[string]$IPRange = $IPRange
		[string]$StartTemp = ""
		[string]$EndTemp = ""
		$UserIPAddressArray = @()
		
		if($IPRange -match "^(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])$") #SINGLE IP
		{
			[String[]]$UserIPAddressArray += $IPRange
		}
		if($IPRange.Contains("/")) #PROCESS A SUBNET STRING
		{
			$IPRangeSplit = $IPRange -split "/"
			[string]$Network = $IPRangeSplit[0]
			if($Network -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
			{
				[string]$Mask = $IPRangeSplit[1]
				
				if($Mask -match "^([0-9]|[1-2][0-9]|30)$")
				{
					
					[Net.IPAddress]$NetworkIPAddress = [System.Net.IPAddress]::Parse($Network)
					[int]$MaskNumber = [int]::Parse($Mask)
					
					[UInt32] $DecimalMaskIP = [Convert]::ToUInt32($(("1" * $MaskNumber).PadRight(32, "0")), 2)
					
					$i = 3; $DecimalNetworkIP = 0;
					$NetworkIPAddress.GetAddressBytes() | ForEach-Object { [UInt32]$DecimalNetworkIP += $_ * [Math]::Pow(256, $i); $i-- }
									
					[UInt32] $NetworkAddressInt = $DecimalNetworkIP -band $DecimalMaskIP
					[UInt32]$InvertedMask = $DecimalMaskIP -bxor 0xFFFFFFFF
					[UInt32] $BroadcastInt = $DecimalNetworkIP -bor $InvertedMask
					
					$StartTempInt = $NetworkAddressInt + 1
					
					$DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
					$Remainder = $StartTempInt % [Math]::Pow(256, $i)
					($StartTempInt - $Remainder) / [Math]::Pow(256, $i)
					$StartTempInt = $Remainder
					} )
					#Start Address
					[string]$StartTemp = [String]::Join('.', $DottedIP)
					
					$EndTempInt = $BroadcastInt - 1
					$DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
					$Remainder = $EndTempInt % [Math]::Pow(256, $i)
					($EndTempInt - $Remainder) / [Math]::Pow(256, $i)
					$EndTempInt = $Remainder
					} )
					#End Address			
					[string]$EndTemp = [String]::Join('.', $DottedIP)
				}
				else
				{
					Write-Host "ERROR: Bad subnet mask." -foreground "red"
				}
			}
			else
			{
				Write-Host "ERROR: Bad network address." -foreground
			}

		}
		else #PROCESS A RANGE STRING
		{
			$IPRangeSplit = $IPRange -split "-"
			[string]$StartTemp = $IPRangeSplit[0]
			[string]$EndTemp = $IPRangeSplit[1]
		}
		#Check IP Addresses
		if($StartTemp -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
		{
			[string]$StartIP = $StartTemp
		}
		else
		{
			[string]$StartIP = ""
		}
		if($EndTemp -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
		{
			[string]$EndIP = $EndTemp
		}
		else
		{
			[string]$EndIP = ""
		}
			
		if($StartIP -ne "" -and $EndIP -ne "")
		{	
			Write-Host ""
			Write-Host "-----------------------------------------------------------------------------------------" -foreground "Green"
			Write-Host "Signing-out Range of IP Addresses $StartIP to $EndIP. Starting Scan!" -foreground "Green"
			Write-Host "-----------------------------------------------------------------------------------------" -foreground "Green"

			# Get Start Time
			$startDTMScan = (Get-Date)
				
			[int]$FirstOctet,[int]$SecondOctet,[int]$ThirdOctet,[int]$FourthOctet = $StartIP.split('.')
			[int]$FirstOctetEnd,[int]$SecondOctetEnd,[int]$ThirdOctetEnd,[int]$FourthOctetEnd = $EndIP.split('.')
				
			$FinalAddressOct1 = ""
			$FinalAddressOct2 = ""
			$FinalAddressOct3 = ""
			$FinalAddressOct4 = ""
			
			
			foreach ($i in ($FirstOctet..$FirstOctetEnd))
			{
				$FinalAddressOct1 = "${i}."
				foreach ($j in ($SecondOctet..$SecondOctetEnd))
				{
					$FinalAddressOct2 = "${FinalAddressOct1}${j}."
					
					foreach ($k in ($ThirdOctet..$ThirdOctetEnd))
					{
						$FinalAddressOct3 = "${FinalAddressOct2}${k}."
					
						foreach ($l in ($FourthOctet..$FourthOctetEnd))
						{
							$FinalAddressOct4 = "${FinalAddressOct3}${l}"
							[string]$ClientIP = $FinalAddressOct4
							[String[]]$UserIPAddressArray += $ClientIP
						}
					}
				}
			}
		}

		# Get Start Time
		$startDTM = (Get-Date)
				
		Write-Host "Starting Device Sign out..." -foreground "green"
		foreach($IPAddress in $UserIPAddressArray)
		{
			if($Script:CancelScan)
			{break}
			
			$ClientIP = $IPAddress
			$ClientPort = $Script:WebServicePort
			$username = $script:AdminUsername
			$password = $script:AdminPassword 
			$UseHTTPS = $Script:UseHTTPS
			
			Write-Verbose "SignOut: $ClientIP $ClientPort $username $password $UseHTTPS" 
			$resultObjectArray += SignOut $ClientIP $ClientPort $username $password $UseHTTPS
			[System.Windows.Forms.Application]::DoEvents()	
		}
		$Script:CancelScan = $false
		
		# Get End Time
		$endDTM = (Get-Date)
		# Echo Time elapsed
		Write-Host "Elapsed Time: $(($endDTM-$startDTM).totalseconds) seconds" -foreground "green"
		Write-Host "-----------------------------------------------------------------------------------------" -foreground "green"
	}
	if($resultObjectArray -ne $null)
	{
		if($OpenUI) #LOAD UI START
		{
			$statusText = ""
			foreach($resultObject in $resultObjectArray)
			{
				$statusText += "----------------------------------------`r`n"
				$statusText += "IP Address: {0}`r`n" -f $resultObject.IPAddress
				if($resultObject.Model -ne ""){$statusText += "Model: {0}`r`n" -f $resultObject.Model}
				if($resultObject.MACAddress -ne ""){$statusText += "MAC Address: {0}`r`n" -f $resultObject.MACAddress}
				$statusText += "Result: {0}`r`n"  -f $resultObject.Result
				$statusText += "----------------------------------------`r`n"
			}
			ResultsDialog $statusText $resultObjectArray
		}
		else
		{
			return $resultObjectArray
		}
	}
}

function GetStatusPhones([Array] $IPRanges)
{
	$resultText = ""
	$resultObjectArray = @()
	foreach($IPRange in $IPRanges)
	{
		
		[string]$IPRange = $IPRange
		
		[string]$StartTemp = ""
		[string]$EndTemp = ""
		$UserIPAddressArray = @()
		
		if($IPRange -match "^(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])$") #SINGLE IP
		{
			[String[]]$UserIPAddressArray += $IPRange
		}
		if($IPRange.Contains("/")) #PROCESS A SUBNET STRING
		{
			$IPRangeSplit = $IPRange -split "/"
			[string]$Network = $IPRangeSplit[0]
			if($Network -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
			{
				[string]$Mask = $IPRangeSplit[1]
				
				if($Mask -match "^([0-9]|[1-2][0-9]|30)$")
				{
					
					[Net.IPAddress]$NetworkIPAddress = [System.Net.IPAddress]::Parse($Network)
					[int]$MaskNumber = [int]::Parse($Mask)
					
					[UInt32] $DecimalMaskIP = [Convert]::ToUInt32($(("1" * $MaskNumber).PadRight(32, "0")), 2)
					
					$i = 3; $DecimalNetworkIP = 0;
					$NetworkIPAddress.GetAddressBytes() | ForEach-Object { [UInt32]$DecimalNetworkIP += $_ * [Math]::Pow(256, $i); $i-- }
									
					[UInt32] $NetworkAddressInt = $DecimalNetworkIP -band $DecimalMaskIP
					[UInt32]$InvertedMask = $DecimalMaskIP -bxor 0xFFFFFFFF
					[UInt32] $BroadcastInt = $DecimalNetworkIP -bor $InvertedMask
					
					$StartTempInt = $NetworkAddressInt + 1
					
					$DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
					$Remainder = $StartTempInt % [Math]::Pow(256, $i)
					($StartTempInt - $Remainder) / [Math]::Pow(256, $i)
					$StartTempInt = $Remainder
					} )
					#Start Address
					[string]$StartTemp = [String]::Join('.', $DottedIP)
					
					$EndTempInt = $BroadcastInt - 1
					$DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
					$Remainder = $EndTempInt % [Math]::Pow(256, $i)
					($EndTempInt - $Remainder) / [Math]::Pow(256, $i)
					$EndTempInt = $Remainder
					} )
					#End Address			
					[string]$EndTemp = [String]::Join('.', $DottedIP)
					
				}
				else
				{
					Write-Host "ERROR: Bad subnet mask." -foreground "red"
				}
			}
			else
			{
				Write-Host "ERROR: Bad network address." -foreground
			}

		}
		else #PROCESS A RANGE STRING
		{
			$IPRangeSplit = $IPRange -split "-"
			[string]$StartTemp = $IPRangeSplit[0]
			[string]$EndTemp = $IPRangeSplit[1]
		}
		#Check IP Addresses
		if($StartTemp -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
		{
			[string]$StartIP = $StartTemp
		}
		else
		{
			[string]$StartIP = ""
		}
		if($EndTemp -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
		{
			[string]$EndIP = $EndTemp
		}
		else
		{
			[string]$EndIP = ""
		}
			
		if($StartIP -ne "" -and $EndIP -ne "")
		{	
			Write-Host ""
			Write-Host "-----------------------------------------------------------------------------------------" -foreground "Green"
			Write-Host "Getting Status of Range of IP Addresses $StartIP to $EndIP. Starting Scan!" -foreground "Green"
			Write-Host "-----------------------------------------------------------------------------------------" -foreground "Green"

			# Get Start Time
			$startDTMScan = (Get-Date)
				
			[int]$FirstOctet,[int]$SecondOctet,[int]$ThirdOctet,[int]$FourthOctet = $StartIP.split('.')
			[int]$FirstOctetEnd,[int]$SecondOctetEnd,[int]$ThirdOctetEnd,[int]$FourthOctetEnd = $EndIP.split('.')
				
			$FinalAddressOct1 = ""
			$FinalAddressOct2 = ""
			$FinalAddressOct3 = ""
			$FinalAddressOct4 = ""
			
								
			foreach ($i in ($FirstOctet..$FirstOctetEnd))
			{
				$FinalAddressOct1 = "${i}."
				foreach ($j in ($SecondOctet..$SecondOctetEnd))
				{
					$FinalAddressOct2 = "${FinalAddressOct1}${j}."
					
					foreach ($k in ($ThirdOctet..$ThirdOctetEnd))
					{
						$FinalAddressOct3 = "${FinalAddressOct2}${k}."
					
						foreach ($l in ($FourthOctet..$FourthOctetEnd))
						{
							$FinalAddressOct4 = "${FinalAddressOct3}${l}"
							[string]$ClientIP = $FinalAddressOct4
							[String[]]$UserIPAddressArray += $ClientIP
						}
					}
				}
			}
		}

		# Get Start Time
		$startDTM = (Get-Date)
				
		Write-Host "Starting Device Status Check..." -foreground "green"
		foreach($IPAddress in $UserIPAddressArray)
		{
			if($Script:CancelScan)
			{break}
			
			$ClientIP = $IPAddress
			$ClientPort = $Script:WebServicePort
			$username = $script:AdminUsername
			$password = $script:AdminPassword 
			$UseHTTPS = $Script:UseHTTPS
			
			Write-Verbose "GetStatus $ClientIP $ClientPort $username $password $UseHTTPS" 
			$resultObjectArray += GetStatus $ClientIP $ClientPort $username $password $UseHTTPS
			[System.Windows.Forms.Application]::DoEvents()	
		}
		$Script:CancelScan = $false
		
		# Get End Time
		$endDTM = (Get-Date)
		# Echo Time elapsed
		Write-Host "Elapsed Time: $(($endDTM-$startDTM).totalseconds) seconds" -foreground "green"
		Write-Host "-----------------------------------------------------------------------------------------" -foreground "green"
		
	
	}
	if($resultObjectArray -ne $null)
	{
		if($OpenUI) #LOAD UI START
		{
			$statusText = ""
			foreach($resultObject in $resultObjectArray)
			{
				$statusText += "----------------------------------------`r`n"
				$statusText += "IP Address: {0}`r`n" -f $resultObject.IPAddress
				if($resultObject.Model -ne ""){$statusText += "Model: {0}`r`n" -f $resultObject.Model}
				if($resultObject.MACAddress -ne ""){$statusText += "MAC Address: {0}`r`n" -f $resultObject.MACAddress}
				if($resultObject.Version -ne ""){$statusText += "Version: {0}`r`n" -f $resultObject.Version}
				$statusText += "Status: {0}`r`n"  -f $resultObject.Result
				$statusText += "----------------------------------------`r`n"
			}
			ResultsDialog $statusText $resultObjectArray
		}
		else
		{
			return $resultObjectArray
		}
	}
}

function RebootPhones([Array] $IPRanges)
{
	$resultObjectArray = @()
	foreach($IPRange in $IPRanges)
	{
		
		[string]$IPRange = $IPRange
		
		[string]$StartTemp = ""
		[string]$EndTemp = ""
		$UserIPAddressArray = @()
		
		if($IPRange -match "^(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])$") #SINGLE IP
		{
			[String[]]$UserIPAddressArray += $IPRange
		}
		if($IPRange.Contains("/")) #PROCESS A SUBNET STRING
		{
			$IPRangeSplit = $IPRange -split "/"
			[string]$Network = $IPRangeSplit[0]
			if($Network -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
			{
				[string]$Mask = $IPRangeSplit[1]
				
				if($Mask -match "^([0-9]|[1-2][0-9]|30)$")
				{
					
					[Net.IPAddress]$NetworkIPAddress = [System.Net.IPAddress]::Parse($Network)
					[int]$MaskNumber = [int]::Parse($Mask)
					
					[UInt32] $DecimalMaskIP = [Convert]::ToUInt32($(("1" * $MaskNumber).PadRight(32, "0")), 2)
					
					$i = 3; $DecimalNetworkIP = 0;
					$NetworkIPAddress.GetAddressBytes() | ForEach-Object { [UInt32]$DecimalNetworkIP += $_ * [Math]::Pow(256, $i); $i-- }
									
					[UInt32] $NetworkAddressInt = $DecimalNetworkIP -band $DecimalMaskIP
					[UInt32]$InvertedMask = $DecimalMaskIP -bxor 0xFFFFFFFF
					[UInt32] $BroadcastInt = $DecimalNetworkIP -bor $InvertedMask
					
					$StartTempInt = $NetworkAddressInt + 1
					
					$DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
					$Remainder = $StartTempInt % [Math]::Pow(256, $i)
					($StartTempInt - $Remainder) / [Math]::Pow(256, $i)
					$StartTempInt = $Remainder
					} )
					#Start Address
					[string]$StartTemp = [String]::Join('.', $DottedIP)
					
					$EndTempInt = $BroadcastInt - 1
					$DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
					$Remainder = $EndTempInt % [Math]::Pow(256, $i)
					($EndTempInt - $Remainder) / [Math]::Pow(256, $i)
					$EndTempInt = $Remainder
					} )
					#End Address			
					[string]$EndTemp = [String]::Join('.', $DottedIP)
					
				}
				else
				{
					Write-Host "ERROR: Bad subnet mask." -foreground "red"
				}
			}
			else
			{
				Write-Host "ERROR: Bad network address." -foreground
			}

		}
		else #PROCESS A RANGE STRING
		{
			$IPRangeSplit = $IPRange -split "-"
			[string]$StartTemp = $IPRangeSplit[0]
			[string]$EndTemp = $IPRangeSplit[1]
		}
		#Check IP Addresses
		if($StartTemp -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
		{
			[string]$StartIP = $StartTemp
		}
		else
		{
			[string]$StartIP = ""
		}
		if($EndTemp -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
		{
			[string]$EndIP = $EndTemp
		}
		else
		{
			[string]$EndIP = ""
		}
			
		if($StartIP -ne "" -and $EndIP -ne "")
		{	
			Write-Host ""
			Write-Host "-----------------------------------------------------------------------------------------" -foreground "Green"
			Write-Host "Restarting Range of IP Addresses $StartIP to $EndIP. Starting Scan!" -foreground "Green"
			Write-Host "-----------------------------------------------------------------------------------------" -foreground "Green"

			# Get Start Time
			$startDTMScan = (Get-Date)
				
			[int]$FirstOctet,[int]$SecondOctet,[int]$ThirdOctet,[int]$FourthOctet = $StartIP.split('.')
			[int]$FirstOctetEnd,[int]$SecondOctetEnd,[int]$ThirdOctetEnd,[int]$FourthOctetEnd = $EndIP.split('.')
				
			$FinalAddressOct1 = ""
			$FinalAddressOct2 = ""
			$FinalAddressOct3 = ""
			$FinalAddressOct4 = ""
										
			foreach ($i in ($FirstOctet..$FirstOctetEnd))
			{
				$FinalAddressOct1 = "${i}."
				foreach ($j in ($SecondOctet..$SecondOctetEnd))
				{
					$FinalAddressOct2 = "${FinalAddressOct1}${j}."
					
					foreach ($k in ($ThirdOctet..$ThirdOctetEnd))
					{
						$FinalAddressOct3 = "${FinalAddressOct2}${k}."
					
						foreach ($l in ($FourthOctet..$FourthOctetEnd))
						{
							$FinalAddressOct4 = "${FinalAddressOct3}${l}"
							[string]$ClientIP = $FinalAddressOct4
							[String[]]$UserIPAddressArray += $ClientIP
						}
					}
				}
			}
		}

		# Get Start Time
		$startDTM = (Get-Date)
				
		Write-Host "Starting Device Status Check..." -foreground "green"
		foreach($IPAddress in $UserIPAddressArray)
		{
			if($Script:CancelScan)
			{break}
			
			$ClientIP = $IPAddress
			$ClientPort = $Script:WebServicePort
			$username = $script:AdminUsername
			$password = $script:AdminPassword 
			$UseHTTPS = $Script:UseHTTPS
			
			Write-Verbose "RebootPhone $ClientIP $ClientPort $username $password $UseHTTPS" 
			$resultObjectArray += RebootPhone $ClientIP $ClientPort $username $password $UseHTTPS
			[System.Windows.Forms.Application]::DoEvents()	
		}
		$Script:CancelScan = $false
		
		# Get End Time
		$endDTM = (Get-Date)
		# Echo Time elapsed
		Write-Host "Elapsed Time: $(($endDTM-$startDTM).totalseconds) seconds" -foreground "green"
		Write-Host "-----------------------------------------------------------------------------------------" -foreground "green"
		
	
	}
	if($resultObjectArray -ne $null)
	{
		if($OpenUI) #LOAD UI START
		{
			$statusText = ""
			foreach($resultObject in $resultObjectArray)
			{
				$statusText += "----------------------------------------`r`n"
				$statusText += "IP Address: {0}`r`n" -f $resultObject.IPAddress
				if($resultObject.Model -ne ""){$statusText += "Model: {0}`r`n" -f $resultObject.Model}
				if($resultObject.MACAddress -ne ""){$statusText += "MAC Address: {0}`r`n" -f $resultObject.MACAddress}
				$statusText += "Result: {0}`r`n"  -f $resultObject.Result
				$statusText += "----------------------------------------`r`n"
			}
			ResultsDialog $statusText $resultObjectArray
		}
		else
		{
			return $resultObjectArray
		}
	}
}


function SetProvisioningServer([string]$ClientIP, [string]$ClientPort,[string]$username,[string]$password,[bool]$UseHTTPS)
{
	Write-Host
	Write-Host "CONNECTING: $ClientIP" -foreground green
	$secpasswd = ConvertTo-SecureString $password -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential ($username, $secpasswd)
	
	$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username,$password)))
	
	$http = "http://"
	if($UseHTTPS)
	{
		$http = "https://"
	}
	
	#<tr>
	#  <td>
	#    <span textid="318">Server Address</span>
	#  </td>
	#  <td>
	#    <input name="444" isrebootrequired="false" helpid="192" value="http://ause.dm" paramname="device.prov.serverName" default="" config="https://ause.dm.sdg.teams.microsoft.com/device/mmiiaacc/0004f28025b416424769040scvT6kYwOEj9lobDtAZ/lang_en/" variabletype="string" min="0" max="255" maxlength="255" hintdivid="provConf.htm_2">
	#  </td>
	#</tr>
	#device.prov.serverName
	#device.prov.serverType
	$ConnectError = $false
	try{
		if($DotNetCoreCommands)
		{
			$r = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/form-submit/auth.htm" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method POST -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0" -TimeoutSec 3 -SkipCertificateCheck
		}
		else
		{
			$r = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/form-submit/auth.htm" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method POST -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0" -TimeoutSec 3
		}
	}
	catch
	{
		Write-Host "ERROR: " $_ -foreground red
		$ConnectError = $true
	}
	
	if($r.StatusCode -eq 200 -and !($r.Content -imatch "INVALID_LOGIN") -and !($ConnectError))
	{
		$cookieSession = $r.Headers."Set-Cookie"
		$sessionC = $cookieSession -split ";"
		$theSession = $sessionC[0].Replace("session=","")
					
		$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
		#$cookie = New-Object System.Net.Cookie 
		#$cookie.Name = "Authorization"
		#$cookie.Value = "Basic $base64AuthInfo"
		#$cookie.Domain = "${ClientIP}"
		#$session.Cookies.Add($cookie);
		$cookie2 = New-Object System.Net.Cookie
		$cookie2.Name = "session"
		$cookie2.Value = $theSession
		$cookie2.Domain = "${ClientIP}"
		$session.Cookies.Add($cookie2)
		#Cookie: Authorization=Basic UG9seWNvbToxMjM0NQ==
		
		#Check index.htm for CSRF support
		#<meta name="csrf-token" content="Tkc3d0pIclpVckU5aXU4UHgvYklDSEx6Y0ZMSWN4ZAA=">
		if($DotNetCoreCommands)
		{
			[string]$csrf = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/index.htm" -Method GET -WebSession $session -SkipCertificateCheck
		}
		else
		{
			[string]$csrf = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/index.htm" -Method GET -WebSession $session
		}
			
		$csrf2 = ""
		if($csrf -Match "<meta name=`"csrf-token`" content=`"") #CSRF SUPPORT
		{
			[string]$csrf1 = ($csrf -Split "<meta name=`"csrf-token`" content=`"")[1]
			$csrf2 = ($csrf1 -Split "`"/>")[0]
			Write-Verbose "CSRF2: $csrf2"
		}
		
		if($csrf2 -ne "")
		{
			if($DotNetCoreCommands)
			{
				[string]$provConfPage = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/provConf.htm" -Method GET -WebSession $session -Headers @{'anti-csrf-token'="$csrf2"; 'Referer'="${http}${ClientIP}/index.htm"} -SkipCertificateCheck
			}
			else
			{
				[string]$provConfPage = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/provConf.htm" -Method GET -WebSession $session -Headers @{'anti-csrf-token'="$csrf2"; 'Referer'="${http}${ClientIP}/index.htm"}
			}
		}
		else
		{
			if($DotNetCoreCommands)
			{
				[string]$provConfPage = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/provConf.htm" -Method GET -WebSession $session -Headers @{'Referer'="${http}${ClientIP}/index.htm"} -SkipCertificateCheck
			}
			else
			{
				[string]$provConfPage = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/provConf.htm" -Method GET -WebSession $session -Headers @{'Referer'="${http}${ClientIP}/index.htm"}
			}
		}
		$allLines = ($provConfPage -Split "<")
		$foundServerName = $false
		$foundServerType = $false
		foreach($line in $allLines)
		{
			#Write-Host $line -foreground yellow
			if($line -Match "paramname=`"device.prov.serverName`"")
			{
				Write-Verbose $line
				$serverName = [regex]::Match($line, '.*input name=\"([0-9]?[0-9]?[0-9])\"\s.*').captures.groups[1].value
				Write-Verbose "INFO: device.prov.serverName setting value: $serverName"  
				$foundServerName = $true
			}
			if($line -Match "paramname=`"device.prov.serverType`"")
			{
				Write-Verbose $line
				$serverType = [regex]::Match($line, '.*select name=\"([0-9]?[0-9]?[0-9])\"\s.*').captures.groups[1].value
				Write-Verbose "INFO: device.prov.serverType setting value: $serverType" 
				$foundServerType = $true
			}
			if($foundServerName -and $foundServerType)
			{
				break
			}
		}
		
		[string] $ProvisioningURLText = Invoke-Expression "`$ProvisioningURLTable.`"${script:Region}`""
		[string]$ProvisioningServerText = "$serverType=3&$serverName=http%3A%2F%2F$ProvisioningURLText"

		if($csrf2 -ne "")
		{
			if($DotNetCoreCommands)
			{
				$response = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/form-submit" -ContentType "application/x-www-form-urlencoded" -body $ProvisioningServerText -WebSession $session -Method POST -Headers @{'anti-csrf-token'="$csrf2"} -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0" -SkipCertificateCheck
			}
			else
			{
				$response = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/form-submit" -ContentType "application/x-www-form-urlencoded" -body $ProvisioningServerText -WebSession $session -Method POST -Headers @{'anti-csrf-token'="$csrf2"} -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0"
			}
		}
		else
		{
			if($DotNetCoreCommands)
			{
				$response = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/form-submit" -ContentType "application/x-www-form-urlencoded" -body $ProvisioningServerText -WebSession $session -Method POST -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0" -SkipCertificateCheck
			}
			else
			{
				$response = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/form-submit" -ContentType "application/x-www-form-urlencoded" -body $ProvisioningServerText -WebSession $session -Method POST -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0"
			}
		}
		
		Write-Verbose "RESPONSE: `"$response`""
	
		if($response -match "CONF_CHANGE")
		{
			$returnObject = [pscustomobject]@{'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = ""; 'Version' = ""; 'Result'="Provisioning successful"}
			
			Write-Host
			Write-Host "-------------------------------------------------" -foreground green
			Write-Host "IP Address: $ClientIP" -foreground green
			Write-Host "Provisioning successful. The device will now reboot and get Teams config/software. This could take 1-10mins." -foreground green
			Write-Host "-------------------------------------------------" -foreground green
			Write-Host
			return $returnObject
		
		}
		elseif($response -match "CONF_NO_CHANGE")
		{
			$returnObject = [pscustomobject]@{'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = ""; 'Version' = ""; 'Result'="ERROR: Provisioning failed. Configuration failed"}
			
			Write-Host "ERROR: Provisioning failed. Configuration failed." -foreground "red"
			return $returnObject
		}
	}
	else
	{
		if(($r.Content -imatch "INVALID_LOGIN"))
		{
			$returnObject = [pscustomobject]@{'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = ""; 'Version' = ""; 'Result'="ERROR: Device password is incorrect"}
			
			Write-Host "ERROR: Device password is incorrect. Please use correct password for device ${ClientIP}" -foreground "red"
			return $returnObject
		}
		else
		{
			$returnObject = [pscustomobject]@{'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = ""; 'Version' = ""; 'Result'="ERROR: Unable to connect to device"}
			
			Write-Host "ERROR: Unable to connect to ${ClientIP}." -foreground "red"
			return $returnObject			
		}			
	}
}


function SignIn([string]$ClientIP, [string]$ClientPort,[string]$username,[string]$password,[bool]$UseHTTPS)
{
	Write-Host
	Write-Host "CONNECTING: $ClientIP" -foreground green
	
	$secpasswd = ConvertTo-SecureString $password -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential ($username, $secpasswd)
	
	$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username,$password)))
	
	$http = "http://"
	if($UseHTTPS)
	{
		$http = "https://"
	}
	
	#<tr>
	#  <td>
	#    <span textid="318">Server Address</span>
	#  </td>
	#  <td>
	#    <input name="444" isrebootrequired="false" helpid="192" value="http://ause.dm" paramname="device.prov.serverName" default="" config="https://ause.dm.sdg.teams.microsoft.com/device/mmiiaacc/0004f28025b416424769040scvT6kYwOEj9lobDtAZ/lang_en/" variabletype="string" min="0" max="255" maxlength="255" hintdivid="provConf.htm_2">
	#  </td>
	#</tr>
	#device.prov.serverName
	#device.prov.serverType
	
	$ConnectError = $false
	try{
		if($DotNetCoreCommands)
		{
			$r = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/form-submit/auth.htm" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method POST -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0" -TimeoutSec 3 -SkipCertificateCheck
		}
		else
		{
			$r = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/form-submit/auth.htm" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method POST -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0" -TimeoutSec 3
		}
	}
	catch
	{
		Write-Host "ERROR: " $_ -foreground red
		$ConnectError = $true
	}
	
	if($r.StatusCode -eq 200 -and !($r.Content -imatch "INVALID_LOGIN") -and !($ConnectError))
	{
		
		$cookieSession = $r.Headers."Set-Cookie"
		$sessionC = $cookieSession -split ";"
		$sesCookieText = $sessionC[0]
		Write-Verbose "SESSION COOKIE: $sesCookieText" 
		$theSession = $sessionC[0].Replace("session=","")
					
		$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
		#$cookie = New-Object System.Net.Cookie 
		#$cookie.Name = "Authorization"
		#$cookie.Value = "Basic $base64AuthInfo"
		#$cookie.Domain = "${ClientIP}"
		#$session.Cookies.Add($cookie);
		$cookie2 = New-Object System.Net.Cookie
		$cookie2.Name = "session"
		$cookie2.Value = $theSession
		$cookie2.Domain = "${ClientIP}"
		$session.Cookies.Add($cookie2)
		
		#Check index.htm for CSRF support
		#<meta name="csrf-token" content="Tkc3d0pIclpVckU5aXU4UHgvYklDSEx6Y0ZMSWN4ZAA=">
		if($DotNetCoreCommands)
		{
			[string]$csrf = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/index.htm" -Method GET -WebSession $session -SkipCertificateCheck
		}
		else
		{
			[string]$csrf = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/index.htm" -Method GET -WebSession $session
		}
		Write-Verbose "CSRF: $csrf"
					
		$csrf2 = ""
		if($csrf -Match "<meta name=`"csrf-token`" content=`"") #CSRF SUPPORT
		{
			[string]$csrf1 = ($csrf -Split "<meta name=`"csrf-token`" content=`"")[1]
			$csrf2 = ($csrf1 -Split "`"/>")[0]
			Write-Verbose "CSRF2: $csrf2"
		}
		

		for($i=0; $i -le 30; $i++) 
		{
			Write-Verbose "INFO: Checking for onboarding URL"
		
			#GET THE PROVISIONING SERVER NAME:
			#config="https://ause.dm.sdg.teams.microsoft.com/device/mmiiaacc/0004f28025b416424769040scvT6kYwOEj9lobDtAZ/lang_en/"
			if($csrf2 -ne "")
			{
				if($DotNetCoreCommands)
				{
					[string]$provConfPage = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/provConf.htm" -Method GET -WebSession $session -Headers @{'anti-csrf-token'="$csrf2"; 'Referer'="${http}${ClientIP}/index.htm"} -SkipCertificateCheck
				}
				else
				{
					[string]$provConfPage = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/provConf.htm" -Method GET -WebSession $session -Headers @{'anti-csrf-token'="$csrf2"; 'Referer'="${http}${ClientIP}/index.htm"}
				}
			}
			else
			{
				if($DotNetCoreCommands)
				{
					[string]$provConfPage = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/provConf.htm" -Method GET -WebSession $session -Headers @{'Referer'="${http}${ClientIP}/index.htm"} -SkipCertificateCheck						
				}
				else
				{
					[string]$provConfPage = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/provConf.htm" -Method GET -WebSession $session -Headers @{'Referer'="${http}${ClientIP}/index.htm"}							
				}
			}
			
			Write-Verbose "Provisioning Page: $provConfPage"
			$allLines = ($provConfPage -Split "<")
			$configLocation = ""
			$breakLoop = $false
			foreach($line in $allLines)
			{
				if($line -Match "paramname=`"device.prov.serverName`"")
				{
					Write-Verbose "$line"
					$firstSplit = ($line -split 'config="')[1]
					$configLocation = ($firstSplit -split '" ')[0]
					Write-Verbose "INFO: get config from here: $configLocation" 
					
					if($configLocation -imatch '.*OnBoarding\/mmiiaacc\/.*')
					{
						Write-Verbose "INFO: Onboarding URL found. Break."
						$breakLoop = $true
					}
					elseif($configLocation -imatch '.*device\/mmiiaacc\/.*')
					{
						Write-Host "INFO: The phone is already signed in." -foreground "yellow"
						$configLocation = "signedin"
						$breakLoop = $true									
					}
					else
					{
						Write-Host "INFO: Config location not available yet. Try again." -foreground "yellow"									
					}
				}
			}
			if($breakLoop)
			{
				break
			}
			
			Write-Host "INFO: Wait 10 seconds and tyring again..." -foreground "yellow"
			Start-Sleep -s 10
		}
				
		if($configLocation -eq "signedin")
		{
			$returnObject = [pscustomobject]@{'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = ""; 'Result'="ERROR: You can't sign in the phone because it's already signed in"}
			
			Write-Host "ERROR: You can't sign in the phone because it's already signed in. Sign out the phone first if you want to sign it in as another number." -foreground red
			$statusText = ""
			$statusText += "----------------------------------------`r`n"
			$statusText += "IP Address: $ClientIP`r`n"
			$statusText += "ERROR: You can't sign in the phone because it's already signed in.`r`n"
			$statusText += "----------------------------------------`r`n"
			return $returnObject		
		}					
		elseif($configLocation -ne "")
		{
			#GET THE CONFIG 000000000000.cfg
			Write-Verbose "${configLocation}000000000000.cfg"
			try{
				if($DotNetCoreCommands)
				{
					$baseConfigFile = Invoke-WebRequest "${configLocation}000000000000.cfg" -UserAgent "FileTransport PolycomVVX-VVX_500-UA/5.9.6.2327 Type/Application" -SkipCertificateCheck
				}
				else
				{
					$baseConfigFile = Invoke-WebRequest "${configLocation}000000000000.cfg" -UserAgent "FileTransport PolycomVVX-VVX_500-UA/5.9.6.2327 Type/Application"
				}
			} 
			catch
			{
				$returnObject = [pscustomobject]@{'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = ""; 'Version' = ""; 'Result'="ERROR: Provisioning failed. Cannot get config file from microsoft. Try again."}
			
				Write-Host "ERROR: Provisioning failed. Cannot get config file from microsoft. Try again." -foreground "red"
				return $returnObject
			}
			Write-Verbose "BASE CONFIG FILE: $baseConfigFile"
			
			if($configLocation -match '.*OnBoarding\/mmiiaacc\/(.{12}).*')
			{
				[string]$MACAddress = [regex]::Match($configLocation, '.*OnBoarding\/mmiiaacc\/(.{12}).*').captures.groups[1].value

				$firstSplit = ($baseConfigFile -split 'CONFIG_FILES="')[1]
				[string]$onBoardingConfigName = ($firstSplit -split '"')[0]
				$onBoardingConfigName = $onBoardingConfigName.Replace("[PHONE_MAC_ADDRESS]", $MACAddress)  
				
				Write-Verbose "configLocation: $configLocation"
				Write-Verbose "Onboarding: $onBoardingConfigName"
				Write-Verbose "${configLocation}${onBoardingConfigName}"
				try
				{
					if($DotNetCoreCommands)
					{
						$onBoardingConfigFile = Invoke-WebRequest "${configLocation}${onBoardingConfigName}" -UserAgent "FileTransport PolycomVVX-VVX_500-UA/5.9.6.2327 Type/Application" -SkipCertificateCheck
					}
					else
					{
						$onBoardingConfigFile = Invoke-WebRequest "${configLocation}${onBoardingConfigName}" -UserAgent "FileTransport PolycomVVX-VVX_500-UA/5.9.6.2327 Type/Application"
					}
				} 
				catch
				{
					$returnObject = [pscustomobject]@{'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = ""; 'Version' = ""; 'Result'="ERROR: Provisioning failed. Cannot get onboarding config from microsoft. Try again."}
				
					Write-Host "ERROR: Provisioning failed. Cannot get onboarding config from microsoft. Try again." -foreground "red"
					return $returnObject
				}
				Write-Verbose "ONBOARDING CONFIG FILE: $onBoardingConfigFile"
				
				#softkey.1.action="https://ause.dm.sdg.teams.microsoft.com/device/softkey.php/mmiiaacc/64167f25128816427657043S47LCEFaH7L33M6XBpK/lang_en/"
								
				$firstSplit = ($onBoardingConfigFile -split 'softkey.1.action="')[1]
				[string]$softKeyButtonURL = ($firstSplit -split '"')[0]
								
				Write-Host "Pressing virtual sign in button!" -foreground green
				Write-Host "$softKeyButtonURL" -foreground green
				Write-Host
				
				for($i=0; $i -le 20; $i++) 
				{
					if($DotNetCoreCommands)
					{
						$authResponse = Invoke-WebRequest "$softKeyButtonURL" -UserAgent "Mozilla/5.0 (QtEmbedded; Android 1.0) AppleWebKit/534.34 (KHTML, like Gecko) browser Safari/534.34 PolycomVVX-VVX_500-UA/5.9.6.2327 (SN:0004f28025b4) Type/Application" -SkipCertificateCheck
					}
					else
					{
						$authResponse = Invoke-WebRequest "$softKeyButtonURL" -UserAgent "Mozilla/5.0 (QtEmbedded; Android 1.0) AppleWebKit/534.34 (KHTML, like Gecko) browser Safari/534.34 PolycomVVX-VVX_500-UA/5.9.6.2327 (SN:0004f28025b4) Type/Application"
					}
					Write-Verbose "AUTH RESPONSE: $authResponse"
					
					#<p><strong>Sign In</strong>: <span style="text-decoration: underline; color: #0000ff;">https://microsoft.com/devicelogin</span></p>
					#<p><strong>Pair Code</strong>: PY89F9J3N</p>
					
					if($authResponse -match '.*Pair\sCode.*:\s(.*)<\/p>.*')
					{
						$PairCode = [regex]::Match($authResponse, '.*Pair\sCode.*:\s(.*)<\/p>.*').captures.groups[1].value
						
						$MACAddress = $MACAddress.ToUpper()
						$MACAddress = $MACAddress -replace '..(?!$)', '$&:'
						
						$returnObject = [pscustomobject]@{'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = "$MACAddress"; 'Version' = ""; 'Result'="Pair Code: $PairCode"; 'URL'='https://microsoft.com/devicelogin'}
			
						Write-Host
						Write-Host "-------------------------------------------------" -foreground green
						Write-Host "IP Address: $ClientIP" -foreground green
						Write-Host "MAC Address: $MACAddress" -foreground green
						Write-Host "URL: https://microsoft.com/devicelogin" -foreground green
						Write-Host "Pair Code: $PairCode" -foreground green
						Write-Host "-------------------------------------------------" -foreground green
						Write-Host
						return $returnObject
						
						break
					}
					
					Write-Host "INFO: Wait 10 seconds and tyring again..." -foreground yellow
					Start-Sleep -s 10
				}
			}
			else
			{
				$returnObject = [pscustomobject]@{'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = ""; 'Result'="ERROR: MAC Address could not be found"; 'URL'=''}
				
				Write-Host "ERROR: MAC Address could not be found." -foreground "red"
				return $returnObject	
			}
		}
		else
		{
			$returnObject = [pscustomobject]@{'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = ""; 'Version' = ""; 'Result'="ERROR: MAC Address could not be found"; 'URL'=''}
				
			Write-Host "ERROR: No config location found" -foreground "red"
			return $returnObject
		}
	}
	else
	{
		if(($r.Content -imatch "INVALID_LOGIN"))
		{
			$returnObject = [pscustomobject]@{'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = ""; 'Version' = ""; 'Result'="ERROR: Device password is incorrect"; 'URL'=''}
			
			Write-Host "ERROR: Device password is incorrect. Please use correct password for device ${ClientIP}" -foreground "red"
			return $returnObject
		}
		else
		{
			$returnObject = [pscustomobject]@{'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = ""; 'Version' = ""; 'Result'="ERROR: Unable to connect to device"; 'URL'=''}
			
			Write-Host "ERROR: Unable to connect to ${ClientIP}." -foreground "red"
			return $returnObject			
		}			
	}
}


function SignOut([string]$ClientIP, [string]$ClientPort,[string]$username,[string]$password,[bool]$UseHTTPS)
{
	Write-Host
	Write-Host "CONNECTING: $ClientIP" -foreground green
	
	$secpasswd = ConvertTo-SecureString $password -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential ($username, $secpasswd)
	
	$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username,$password)))
	
	$http = "http://"
	if($UseHTTPS)
	{
		$http = "https://"
	}

	#softkey.1.action="$FDoNotDisturb$"
	#softkey.2.action="1$AVoiceMail$"
	#softkey.3.action="$FCallList$"
	#softkey.4.action="https://ause.dm.sdg.teams.microsoft.com/device/logout.php/mmiiaacc/64167f2512881642852519eK5g76EcGLu04u1WHKdW/lang_en/"
	#softkey.1.enable="1"
	#softkey.2.enable="1"
	$ConnectError = $false
	try{
		if($DotNetCoreCommands)
		{
			$r = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/form-submit/auth.htm" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method POST -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0" -TimeoutSec 3 -SkipCertificateCheck
		}
		else
		{
			$r = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/form-submit/auth.htm" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method POST -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0" -TimeoutSec 3
		}
	}
	catch
	{
		Write-Host "ERROR: " $_ -foreground red	
		$ConnectError = $true		
	}
	
	if($r.StatusCode -eq 200 -and !($r.Content -imatch "INVALID_LOGIN") -and !($ConnectError))
	{
		$cookieSession = $r.Headers."Set-Cookie"
		$sessionC = $cookieSession -split ";"
		$sessionText = $sessionC[0]
		Write-Verbose "SESSION COOKIE: $sessionText" 
		$theSession = $sessionC[0].Replace("session=","")
					
		$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
		#$cookie = New-Object System.Net.Cookie 
		#$cookie.Name = "Authorization"
		#$cookie.Value = "Basic $base64AuthInfo"
		#$cookie.Domain = "${ClientIP}"
		#$session.Cookies.Add($cookie);
		$cookie2 = New-Object System.Net.Cookie
		$cookie2.Name = "session"
		$cookie2.Value = $theSession
		$cookie2.Domain = "${ClientIP}"
		$session.Cookies.Add($cookie2)
		#Cookie: Authorization=Basic UG9seWNvbToxMjM0NQ==
		
		#Check index.htm for CSRF support
		#<meta name="csrf-token" content="Tkc3d0pIclpVckU5aXU4UHgvYklDSEx6Y0ZMSWN4ZAA=">
		if($DotNetCoreCommands)
		{
			[string]$csrf = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/index.htm" -Method GET -WebSession $session -SkipCertificateCheck
		}
		else
		{
			[string]$csrf = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/index.htm" -Method GET -WebSession $session
		}
				
		$csrf2 = ""
		if($csrf -Match "<meta name=`"csrf-token`" content=`"") #CSRF SUPPORT
		{
			[string]$csrf1 = ($csrf -Split "<meta name=`"csrf-token`" content=`"")[1]
			$csrf2 = ($csrf1 -Split "`"/>")[0]
			Write-Verbose "CSRF2: $csrf2"
		}
				
		Write-Verbose "Getting for onboarding URL!"
	
		#GET THE PROVISIONING SERVER NAME:
		#config="https://ause.dm.sdg.teams.microsoft.com/device/mmiiaacc/0004f28025b416424769040scvT6kYwOEj9lobDtAZ/lang_en/"
		if($csrf2 -ne "")
		{
			if($DotNetCoreCommands)
			{
				[string]$provConfPage = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/provConf.htm" -Method GET -WebSession $session -Headers @{'anti-csrf-token'="$csrf2"; 'Referer'="${http}${ClientIP}/index.htm"} -SkipCertificateCheck
			}
			else
			{
				[string]$provConfPage = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/provConf.htm" -Method GET -WebSession $session -Headers @{'anti-csrf-token'="$csrf2"; 'Referer'="${http}${ClientIP}/index.htm"}
			}
		}
		else
		{	
			if($DotNetCoreCommands)
			{
				[string]$provConfPage = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/provConf.htm" -Method GET -WebSession $session -Headers @{'Referer'="${http}${ClientIP}/index.htm"} -SkipCertificateCheck
			}
			else
			{
				[string]$provConfPage = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/provConf.htm" -Method GET -WebSession $session -Headers @{'Referer'="${http}${ClientIP}/index.htm"}
			}
		}
		
		$allLines = ($provConfPage -Split "<")
		$configLocation = ""
		foreach($line in $allLines)
		{
			if($line -Match "paramname=`"device.prov.serverName`"")
			{
				Write-Verbose "$line"
				$firstSplit = ($line -split 'config="')[1]
				$configLocation = ($firstSplit -split '" ')[0]
				Write-Verbose "INFO: get config from here: $configLocation"
				
				if($configLocation -imatch '.*device\/mmiiaacc\/.*')
				{
					Write-Verbose "Onboarding URL found. Break."
					break
				}
				else
				{
					Write-Host "INFO: Config location not available yet. Try again." -foreground "yellow"									
				}
			}
		}
	
		if($configLocation -ne "")
		{
			#GET THE CONFIG 000000000000.cfg
			Write-Verbose "${configLocation}000000000000.cfg"
			try{
				if($DotNetCoreCommands)
				{
					$baseConfigFile = Invoke-WebRequest "${configLocation}000000000000.cfg" -UserAgent "FileTransport PolycomVVX-VVX_500-UA/5.9.6.2327 Type/Application" -SkipCertificateCheck
				}
				else
				{
					$baseConfigFile = Invoke-WebRequest "${configLocation}000000000000.cfg" -UserAgent "FileTransport PolycomVVX-VVX_500-UA/5.9.6.2327 Type/Application"
				}
			} 
			catch
			{
				$returnObject = [pscustomobject]@{'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = ""; 'Version' = ""; 'Result'="ERROR: Provisioning failed. Cannot get config file from microsoft. Try again."}
			
				Write-Host "ERROR: Provisioning failed. Cannot get config file from microsoft. Try again." -foreground "red"
				return $returnObject
			}
			Write-Verbose "BASE CONFIG FILE: $baseConfigFile"
			
			if($configLocation -match '.*device\/mmiiaacc\/(.{12}).*')
			{
				$MACAddress = [regex]::Match($configLocation, '.*device\/mmiiaacc\/(.{12}).*').captures.groups[1].value
			
			
				$firstSplit = ($baseConfigFile -split 'CONFIG_FILES="')[1]
				[string]$onBoardingConfigName = ($firstSplit -split '"')[0]
				$onBoardingConfigName = $onBoardingConfigName.Replace("[PHONE_MAC_ADDRESS]", $MACAddress)  
				
				Write-Verbose "configLocation: $configLocation"
				Write-Verbose "Onboarding: $onBoardingConfigName"
				Write-Verbose "${configLocation}${onBoardingConfigName}"
				try
				{
					if($DotNetCoreCommands)
					{
						$onBoardingConfigFile = Invoke-WebRequest "${configLocation}${onBoardingConfigName}" -UserAgent "FileTransport PolycomVVX-VVX_500-UA/5.9.6.2327 Type/Application" -SkipCertificateCheck
					}
					else
					{
						$onBoardingConfigFile = Invoke-WebRequest "${configLocation}${onBoardingConfigName}" -UserAgent "FileTransport PolycomVVX-VVX_500-UA/5.9.6.2327 Type/Application"
					}
				} 
				catch
				{
					$returnObject = [pscustomobject]@{'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = ""; 'Version' = ""; 'Result'="ERROR: Provisioning failed. Cannot get onboarding config from microsoft. Try again."}
				
					Write-Host "ERROR: Provisioning failed. Cannot get onboarding config from microsoft. Try again." -foreground "red"
					return $returnObject
				}
				Write-Verbose "ONBOARDING CONFIG FILE: $onBoardingConfigFile"
								
				#softkey.4.action="https://ause.dm.sdg.teams.microsoft.com/device/logout.php/mmiiaacc/64167f2512881642852519eK5g76EcGLu04u1WHKdW/lang_en/"

				#Find the softkey
				$foundSoftkeyResult = [regex]::Match($onBoardingConfigFile, '.*(softkey\..\.action=\")https:\/\/.*logout.php')
				if($foundSoftkeyResult.Success -eq $True)
				{
					$foundSoftkey = $foundSoftkeyResult.captures.groups[1].value
					Write-Verbose "SOFTKEY: $foundSoftkey"
											
											
					$firstSplit = ($onBoardingConfigFile -split $foundSoftkey)[1]
					[string]$softKeyButtonURL = ($firstSplit -split '"')[0]
					
					Write-Verbose "Soft Key URL: $softKeyButtonURL"
					Write-Host "Pressing virtual sign out button!" -foreground "green"
					Write-Host
					try
					{
						if($DotNetCoreCommands)
						{					
							$authResponse = Invoke-WebRequest "$softKeyButtonURL" -UserAgent "Mozilla/5.0 (QtEmbedded; Android 1.0) AppleWebKit/534.34 (KHTML, like Gecko) browser Safari/534.34 PolycomVVX-VVX_500-UA/5.9.6.2327 (SN:0004f28025b4) Type/Application" -SkipCertificateCheck
						}
						else
						{
							$authResponse = Invoke-WebRequest "$softKeyButtonURL" -UserAgent "Mozilla/5.0 (QtEmbedded; Android 1.0) AppleWebKit/534.34 (KHTML, like Gecko) browser Safari/534.34 PolycomVVX-VVX_500-UA/5.9.6.2327 (SN:0004f28025b4) Type/Application"
						}
					}
					catch
					{
						$returnObject = [pscustomobject]@{'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = ""; 'Version' = ""; 'Result'="ERROR: Provisioning failed. Cannot connect to Microsoft sign out URL."}
				
						Write-Host "ERROR: Provisioning failed. Cannot connect to Microsoft sign out URL." -foreground "red"
						return $returnObject
					}
					#<!DOCTYPE html>
					#<html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
					#<title>Sign Out</title>
					#<meta name="viewport" content="width=device-width, initial-scale=1">
					#</head>
					#<body>
					#
					#<div>
					#		  <p><b>Signed Out Successfully</b></p>
					#	
					#</div>
					#</body></html>
					#
					
					Write-Verbose $authResponse
					
					$MACAddress = $MACAddress.ToUpper()
					$MACAddress = $MACAddress -replace '..(?!$)', '$&:'
					
					if($authResponse -match '.*Signed Out Successfully.*')
					{
						$returnObject = [pscustomobject]@{ 'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = "$MACAddress"; 'Version' = ""; 'Result'="Signed Out"}
			
						Write-Host
						Write-Host "-------------------------------------------------" -foreground "green"
						Write-Host "IP Address: $ClientIP" -foreground green
						Write-Host "MAC Address: $MACAddress" -foreground green
						Write-Host "Signed Out!" -foreground green
						Write-Host "-------------------------------------------------" -foreground "green"
						Write-Host
						return $returnObject
						#break
					}
					else
					{
						$returnObject = [pscustomobject]@{'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = "$MACAddress"; 'Version' = ""; 'Result'="ERROR: Sign out failed"}
						
						Write-Host
						Write-Host "-------------------------------------------------" -foreground "red"
						Write-Host "IP Address: $ClientIP" -foreground red
						Write-Host "MAC Address: $MACAddress" -foreground red
						Write-Host "Sign out failed." -foreground red
						Write-Host "-------------------------------------------------" -foreground "red"
						Write-Host
						return $returnObject
					}
				}
				else
				{
					Write-Host "ERROR: Can't find sign out soft key in config" -foreground "red"
				}
			}
			else
			{
				$returnObject = [pscustomobject]@{'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = ""; 'Version' = ""; 'Result'="ERROR: Device is not signed in"}
				Write-Host "ERROR: Device is not signed in" -foreground "red"
				return $returnObject
			}
		}
		else
		{
			$returnObject = [pscustomobject]@{'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = ""; 'Version' = ""; 'Result'="ERROR: No config location found"}
			
			Write-Host "ERROR: No config location found" -foreground "red"
			return $returnObject
		}
	}
	else
	{
		if(($r.Content -imatch "INVALID_LOGIN"))
		{
			$returnObject = [pscustomobject]@{'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = ""; 'Version' = ""; 'Result'="ERROR: Device password is incorrect"}
			
			Write-Host "ERROR: Device password is incorrect. Please use correct password for device ${ClientIP}" -foreground "red"
			return $returnObject
		}
		else
		{
			$returnObject = [pscustomobject]@{'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = ""; 'Version' = ""; 'Result'="ERROR: Unable to connect to device"}
			
			Write-Host "ERROR: Unable to connect to ${ClientIP}." -foreground "red"
			return $returnObject
		}			
	}
}



function GetStatus([string]$ClientIP, [string]$ClientPort,[string]$username,[string]$password,[bool]$UseHTTPS)
{
	Write-Host
	Write-Host "CONNECTING: $ClientIP" -foreground green
	$secpasswd = ConvertTo-SecureString $password -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential ($username, $secpasswd)
	
	$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username,$password)))
	
	$http = "http://"
	if($UseHTTPS)
	{
		$http = "https://"
	}

	#<tr>
	#  <td>
	#    <span textid="318">Server Address</span>
	#  </td>
	#  <td>
	#    <input name="444" isrebootrequired="false" helpid="192" value="http://ause.dm" paramname="device.prov.serverName" default="" config="https://ause.dm.sdg.teams.microsoft.com/device/mmiiaacc/0004f28025b416424769040scvT6kYwOEj9lobDtAZ/lang_en/" variabletype="string" min="0" max="255" maxlength="255" hintdivid="provConf.htm_2">
	#  </td>
	#</tr>
	#device.prov.serverName
	#device.prov.serverType
	
	$ConnectError = $false
	try{
		if($DotNetCoreCommands)
		{
			$r = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/form-submit/auth.htm" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method POST -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0" -TimeoutSec 3 -SkipCertificateCheck
		}
		else
		{
			$r = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/form-submit/auth.htm" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method POST -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0" -TimeoutSec 3
		}
	}
	catch
	{
		Write-Host "ERROR: " $_ -foreground red
		$ConnectError = $true
	}
	
	if($r.StatusCode -eq 200 -and !($r.Content -imatch "INVALID_LOGIN") -and !($ConnectError))
	{
		$cookieSession = $r.Headers."Set-Cookie"
		$sessionC = $cookieSession -split ";"
		$sessionText = $sessionC[0]
		Write-Verbose "SESSION COOKIE: $sessionText" 
		$theSession = $sessionC[0].Replace("session=","")
					
		$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
		#$cookie = New-Object System.Net.Cookie 
		#$cookie.Name = "Authorization"
		#$cookie.Value = "Basic $base64AuthInfo"
		#$cookie.Domain = "${ClientIP}"
		#$session.Cookies.Add($cookie);
		$cookie2 = New-Object System.Net.Cookie
		$cookie2.Name = "session"
		$cookie2.Value = $theSession
		$cookie2.Domain = "${ClientIP}"
		$session.Cookies.Add($cookie2)
		#Cookie: Authorization=Basic UG9seWNvbToxMjM0NQ==
		
		#Check index.htm for CSRF support
		#<meta name="csrf-token" content="Tkc3d0pIclpVckU5aXU4UHgvYklDSEx6Y0ZMSWN4ZAA=">
		if($DotNetCoreCommands)
		{
			$csrf = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/index.htm" -Method GET -WebSession $session -SkipCertificateCheck
		}
		else
		{
			$csrf = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/index.htm" -Method GET -WebSession $session
		}
		#GET PHONE INFO
		#    <div id="home">

		$csrf2 = ""		
		if($csrf -Match "<meta name=`"csrf-token`" content=`"") #CSRF SUPPORT
		{
			[string]$csrf1 = ($csrf -Split "<meta name=`"csrf-token`" content=`"")[1]
			$csrf2 = ($csrf1 -Split "`"/>")[0]
			Write-Verbose "CSRF2: $csrf2"
		}
			
		if($csrf2 -ne "") #CSRF SUPPORT
		{
			if($DotNetCoreCommands)
			{
				[string]$provConfPage = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/provConf.htm" -Method GET -WebSession $session -Headers @{'anti-csrf-token'="$csrf2"; 'Referer'="${http}${ClientIP}/index.htm"} -SkipCertificateCheck
			}
			else
			{
				[string]$provConfPage = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/provConf.htm" -Method GET -WebSession $session -Headers @{'anti-csrf-token'="$csrf2"; 'Referer'="${http}${ClientIP}/index.htm"}
			}
		}
		else
		{
			if($DotNetCoreCommands)
			{
				[string]$provConfPage = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/provConf.htm" -Method GET -WebSession $session -Headers @{'Referer'="${http}${ClientIP}/index.htm"} -SkipCertificateCheck
			}
			else
			{
				[string]$provConfPage = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/provConf.htm" -Method GET -WebSession $session -Headers @{'Referer'="${http}${ClientIP}/index.htm"}
			}
		}
		
		$allLines = ($provConfPage -Split "<")
		$foundServerName = $false
		$foundServerType = $false
		foreach($line in $allLines)
		{
			if($line -Match "paramname=`"device.prov.serverName`"")
			{
				Write-Verbose $line
				$serverName = [regex]::Match($line, '.*input name=\"([0-9]?[0-9]?[0-9])\"\s.*').captures.groups[1].value
				Write-Verbose "device.prov.serverName setting value: $serverName" # -foreground yellow
			
				$firstSplit = ($line -split 'config="')[1]
				$configLocation = ($firstSplit -split '" ')[0]
				Write-Verbose "INFO: get config from here: $configLocation"
				$foundServerName = $true
			
			}
			if($line -Match "paramname=`"device.prov.serverType`"")
			{
				Write-Verbose $line
				$serverType = [regex]::Match($line, '.*select name=\"([0-9]?[0-9]?[0-9])\"\s.*').captures.groups[1].value
				Write-Verbose "device.prov.serverType setting value: $serverType"  #-foreground yellow
				$foundServerType = $true
			}
			if($foundServerName -and $foundServerType)
			{
				break
			}
		}
		
		if($csrf2 -ne "") #CSRF SUPPORT
		{
			if($DotNetCoreCommands)
			{
				[string]$homePage = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/home.htm" -Method GET -WebSession $session -Headers @{'anti-csrf-token'="$csrf2"; 'Referer'="${http}${ClientIP}/index.htm"} -SkipCertificateCheck
			}
			else
			{
				[string]$homePage = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/home.htm" -Method GET -WebSession $session -Headers @{'anti-csrf-token'="$csrf2"; 'Referer'="${http}${ClientIP}/index.htm"}
			}
		}
		else
		{
			if($DotNetCoreCommands)
			{
				[string]$homePage = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/home.htm" -Method GET -WebSession $session -Headers @{'Referer'="${http}${ClientIP}/index.htm"} -SkipCertificateCheck
			}
			else
			{
				[string]$homePage = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/home.htm" -Method GET -WebSession $session -Headers @{'Referer'="${http}${ClientIP}/index.htm"}
			}
		}
		Write-Verbose $homePage
		if($homePage -Match '.*<td>[\n\r\s]*(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))[\n\r\s]*</td>.*')
		{
			$MACAddress = [regex]::Match($homePage, '.*<td>[\n\r\s]*(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))[\n\r\s]*</td>.*').captures.groups[1].value
		}
			
		 #<td id="phoneModelInformationTd">
		 #  VVX 411
		 #</td>
		
		if($homePage -Match '.*<td id="phoneModelInformationTd">[\n\r\s]*(VVX[\s]*([0-9]{3}))[\n\r\s]*<\/td>.*')
		{
			$Model = [regex]::Match($homePage, '.*<td id="phoneModelInformationTd">[\n\r\s]*(VVX[\s]*([0-9]{3}))[\n\r\s]*<\/td>.*').captures.groups[1].value
		}
		
		#<td id="UCS_software_version">
        #  5.9.6.2327
        #</td>
		
		if($homePage -Match '.*<td id="UCS_software_version">[\n\r\s]*([0-9]\.[0-9]\.[0-9]\.[0-9][0-9][0-9][0-9])[\n\r\s]*<\/td>.*')
		{
			$Version = [regex]::Match($homePage, '.*<td id="UCS_software_version">[\n\r\s]*([0-9]\.[0-9]\.[0-9]\.[0-9][0-9][0-9][0-9])[\n\r\s]*<\/td>.*').captures.groups[1].value
		}
		
		if($configLocation -imatch '.*OnBoarding\/mmiiaacc\/.*')
		{
			$returnObject = [pscustomobject]@{ 'IPAddress' = "$ClientIP"; 'Model' = "$Model"; 'MACAddress' = "$MACAddress"; 'Version' = "$Version"; 'Result'="Provisioned and signed out"}
			Write-Host
			Write-Host "-------------------------------------------------" -foreground green
			Write-Host "IP Address: $ClientIP" -foreground green
			Write-Host "Model: $Model" -foreground green
			Write-Host "MAC Address: $MACAddress" -foreground green
			Write-Host "Version: $Version" -foreground green
			Write-Host "Status: Provisioned and signed out" -foreground green
			Write-Host "-------------------------------------------------" -foreground green
			Write-Host
		}
		elseif($configLocation -imatch '.*device\/mmiiaacc\/.*')
		{
			$returnObject = [pscustomobject]@{ 'IPAddress' = "$ClientIP"; 'Model' = "$Model"; 'MACAddress' = "$MACAddress"; 'Version' = "$Version"; 'Result'="Provisioned and signed in"}
			Write-Host
			Write-Host "-------------------------------------------------" -foreground green
			Write-Host "IP Address: $ClientIP" -foreground green
			Write-Host "Model: $Model" -foreground green
			Write-Host "MAC Address: $MACAddress" -foreground green
			Write-Host "Version: $Version" -foreground green
			Write-Host "Status: Provisioned and signed in" -foreground green
			Write-Host "-------------------------------------------------" -foreground green
			Write-Host
		}
		elseif($configLocation -eq '')
		{
			$returnObject = [pscustomobject]@{ 'IPAddress' = "$ClientIP"; 'Model' = "$Model"; 'MACAddress' = "$MACAddress"; 'Version' = "$Version"; 'Result'="Not provisioned for Teams"}
			Write-Host
			Write-Host "-------------------------------------------------" -foreground green
			Write-Host "IP Address: $ClientIP" -foreground green
			Write-Host "Model: $Model" -foreground green
			Write-Host "MAC Address: $MACAddress" -foreground green
			Write-Host "Version: $Version" -foreground green
			Write-Host "Status: Not provisioned for Teams" -foreground green
			Write-Host "-------------------------------------------------" -foreground green
			Write-Host
		}
		else
		{
			$returnObject = [pscustomobject]@{ 'IPAddress' = "$ClientIP"; 'Model' = "$Model"; 'MACAddress' = "$MACAddress"; 'Version' = "$Version"; 'Result'="Not provisioned for Teams"}
			Write-Host
			Write-Host "-------------------------------------------------" -foreground green
			Write-Host "IP Address: $ClientIP" -foreground green
			Write-Host "Model: $Model" -foreground green
			Write-Host "MAC Address: $MACAddress" -foreground green
			Write-Host "Version: $Version" -foreground green
			Write-Host "Status: Not provisioned for Teams" -foreground green
			Write-Host "-------------------------------------------------" -foreground green
			Write-Host
		}
		
		return $returnObject
	
	}
	else
	{
		if(($r.Content -imatch "INVALID_LOGIN"))
		{
			$returnObject = [pscustomobject]@{ 'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = ""; 'Version' = ""; 'Result'="ERROR: Device password is incorrect"}
			Write-Host "ERROR: Device password is incorrect. Please use correct password for device ${ClientIP}" -foreground "red"
			return $returnObject
		}
		else
		{
			$returnObject = [pscustomobject]@{ 'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = ""; 'Version' = ""; 'Result'="ERROR: Unable to connect to device"}
			Write-Host "ERROR: Unable to connect to ${ClientIP}." -foreground "red"	
			return $returnObject
		}				
	}
}


function PasswordChange([string]$ClientIP, [string]$ClientPort,[string]$username,[string]$password,[bool]$UseHTTPS, [string]$NewPassword)
{
	Write-Host
	Write-Host "CONNECTING: $ClientIP" -foreground green
	$secpasswd = ConvertTo-SecureString $password -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential ($username, $secpasswd)
	
	$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username,$password)))
	
	$http = "http://"
	if($UseHTTPS)
	{
		$http = "https://"
	}
	
	#<tr>
	#  <td>
	#    <span textid="318">Server Address</span>
	#  </td>
	#  <td>
	#    <input name="444" isrebootrequired="false" helpid="192" value="http://ause.dm" paramname="device.prov.serverName" default="" config="https://ause.dm.sdg.teams.microsoft.com/device/mmiiaacc/0004f28025b416424769040scvT6kYwOEj9lobDtAZ/lang_en/" variabletype="string" min="0" max="255" maxlength="255" hintdivid="provConf.htm_2">
	#  </td>
	#</tr>
	#device.prov.serverName
	#device.prov.serverType
	$ConnectError = $false
	try{
		if($DotNetCoreCommands)
		{
			$r = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/form-submit/auth.htm" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method POST -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0" -TimeoutSec 3 -SkipCertificateCheck
		}
		else
		{
			$r = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/form-submit/auth.htm" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method POST -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0" -TimeoutSec 3
		}
	}
	catch
	{
		Write-Host "ERROR: " $_ -foreground red
		$ConnectError = $true
	}
	
	if($r.StatusCode -eq 200 -and !($r.Content -imatch "INVALID_LOGIN") -and !($ConnectError))
	{
		$cookieSession = $r.Headers."Set-Cookie"
		$sessionC = $cookieSession -split ";"
		$theSession = $sessionC[0].Replace("session=","")
					
		$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
		#$cookie = New-Object System.Net.Cookie 
		#$cookie.Name = "Authorization"
		#$cookie.Value = "Basic $base64AuthInfo"
		#$cookie.Domain = "${ClientIP}"
		#$session.Cookies.Add($cookie);
		$cookie2 = New-Object System.Net.Cookie
		$cookie2.Name = "session"
		$cookie2.Value = $theSession
		$cookie2.Domain = "${ClientIP}"
		$session.Cookies.Add($cookie2)
		#Cookie: Authorization=Basic UG9seWNvbToxMjM0NQ==
		
		#Check index.htm for CSRF support
		#<meta name="csrf-token" content="Tkc3d0pIclpVckU5aXU4UHgvYklDSEx6Y0ZMSWN4ZAA=">
		if($DotNetCoreCommands)
		{
			[string]$csrf = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/index.htm" -Method GET -WebSession $session -SkipCertificateCheck
		}
		else
		{
			[string]$csrf = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/index.htm" -Method GET -WebSession $session
		}
		
		$csrf2 = ""
		if($csrf -Match "<meta name=`"csrf-token`" content=`"") #CSRF SUPPORT
		{
			[string]$csrf1 = ($csrf -Split "<meta name=`"csrf-token`" content=`"")[1]
			$csrf2 = ($csrf1 -Split "`"/>")[0]
			Write-Verbose "CSRF2: $csrf2"
		}

		[string]$PasswordPostText = "oldadminpswd=${password}&newadminpswd=${NewPassword}&cnfmadminpswd=${NewPassword}"
		
		if($csrf2 -ne "")
		{
			if($DotNetCoreCommands)
			{
				$response = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/form-submit/Settings/ChangePassword" -ContentType "application/x-www-form-urlencoded" -body $PasswordPostText -WebSession $session -Method POST -Headers @{'anti-csrf-token'="$csrf2"} -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0" -SkipCertificateCheck
			}
			else
			{
				$response = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/form-submit/Settings/ChangePassword" -ContentType "application/x-www-form-urlencoded" -body $PasswordPostText -WebSession $session -Method POST -Headers @{'anti-csrf-token'="$csrf2"} -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0"
			}
		}
		else
		{
			if($DotNetCoreCommands)
			{
				$response = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/form-submit/Settings/ChangePassword" -ContentType "application/x-www-form-urlencoded" -body $PasswordPostText -WebSession $session -Method POST -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0" -SkipCertificateCheck
			}
			else
			{
				$response = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/form-submit/Settings/ChangePassword" -ContentType "application/x-www-form-urlencoded" -body $PasswordPostText -WebSession $session -Method POST -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0"
			}
		}
		
		Write-Verbose "RESPONSE: `"$response`""
	
		if($response -match "CONF_CHANGE")
		{
			$returnObject = [pscustomobject]@{ 'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = "$MACAddress"; 'Version' = ""; 'Result'="Change of password successful"}
			Write-Host
			Write-Host
			Write-Host "-------------------------------------------------" -foreground green
			Write-Host "IP Address: $ClientIP" -foreground green
			Write-Host "MAC Address: $MACAddress" -foreground green
			Write-Host "Change of password successful." -foreground green
			Write-Host "-------------------------------------------------" -foreground green
			Write-Host
			return $returnObject
		
		}
		elseif($response -match "CONF_NO_CHANGE")
		{
			$returnObject = [pscustomobject]@{ 'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = "$MACAddress"; 'Version' = ""; 'Result'="ERROR: Change of password failed"}
			Write-Host "ERROR: Provisioning failed. Configuration failed." -foreground "red"
			return $returnObject
		}
	}
	else
	{
		if(($r.Content -imatch "INVALID_LOGIN"))
		{
			$returnObject = [pscustomobject]@{ 'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = "$MACAddress"; 'Version' = ""; 'Result'="ERROR: Change of password failed"}
			Write-Host "ERROR: Device password is incorrect. Please use correct password for device ${ClientIP}" -foreground "red"
			return $returnObject
		}
		else
		{
			$returnObject = [pscustomobject]@{ 'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = "$MACAddress"; 'Version' = ""; 'Result'="ERROR: Unable to connect to device."}
			Write-Host "ERROR: Unable to connect to ${ClientIP}." -foreground "red"
			return $returnObject			
		}			
	}
}


function RebootPhone([string]$ClientIP, [string]$ClientPort,[string]$username,[string]$password,[bool]$UseHTTPS)
{
	Write-Host
	Write-Host "CONNECTING: $ClientIP" -foreground green
	$secpasswd = ConvertTo-SecureString $password -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential ($username, $secpasswd)
	
	$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username,$password)))
	
	$http = "http://"
	if($UseHTTPS)
	{
		$http = "https://"
	}
	
	#<tr>
	#  <td>
	#    <span textid="318">Server Address</span>
	#  </td>
	#  <td>
	#    <input name="444" isrebootrequired="false" helpid="192" value="http://ause.dm" paramname="device.prov.serverName" default="" config="https://ause.dm.sdg.teams.microsoft.com/device/mmiiaacc/0004f28025b416424769040scvT6kYwOEj9lobDtAZ/lang_en/" variabletype="string" min="0" max="255" maxlength="255" hintdivid="provConf.htm_2">
	#  </td>
	#</tr>
	#device.prov.serverName
	#device.prov.serverType
	$ConnectError = $false
	try{
		if($DotNetCoreCommands)
		{
			$r = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/form-submit/auth.htm" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method POST -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0" -TimeoutSec 3 -SkipCertificateCheck
		}
		else
		{
			$r = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/form-submit/auth.htm" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method POST -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0" -TimeoutSec 3
		}
	}
	catch
	{
		Write-Host "ERROR: " $_ -foreground red
		$ConnectError = $true
	}
	
	if($r.StatusCode -eq 200 -and !($r.Content -imatch "INVALID_LOGIN") -and !($ConnectError))
	{
		#Write-Host "RESPONSE: " $r.Headers
		$cookieSession = $r.Headers."Set-Cookie"
		$sessionC = $cookieSession -split ";"
		#Write-Host "SESSION COOKIE: " $sessionC[0]
		$theSession = $sessionC[0].Replace("session=","")
					
		$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
		#$cookie = New-Object System.Net.Cookie 
		#$cookie.Name = "Authorization"
		#$cookie.Value = "Basic $base64AuthInfo"
		#$cookie.Domain = "${ClientIP}"
		#$session.Cookies.Add($cookie);
		$cookie2 = New-Object System.Net.Cookie
		$cookie2.Name = "session"
		$cookie2.Value = $theSession
		$cookie2.Domain = "${ClientIP}"
		$session.Cookies.Add($cookie2)
		#Cookie: Authorization=Basic UG9seWNvbToxMjM0NQ==
		
		#Check index.htm for CSRF support
		#<meta name="csrf-token" content="Tkc3d0pIclpVckU5aXU4UHgvYklDSEx6Y0ZMSWN4ZAA=">
		if($DotNetCoreCommands)
		{
			[string]$csrf = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/index.htm" -Method GET -WebSession $session -SkipCertificateCheck
		}
		else
		{
			[string]$csrf = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/index.htm" -Method GET -WebSession $session
		}
			
		$csrf2 = ""
		if($csrf -Match "<meta name=`"csrf-token`" content=`"") #CSRF SUPPORT
		{
			[string]$csrf1 = ($csrf -Split "<meta name=`"csrf-token`" content=`"")[1]
			$csrf2 = ($csrf1 -Split "`"/>")[0]
			Write-Verbose "CSRF2: $csrf2"
		}

		[string]$PasswordPostText = "oldadminpswd=${password}&newadminpswd=${NewPassword}&cnfmadminpswd=${NewPassword}"
			
		
		if($csrf2 -ne "")
		{
			if($DotNetCoreCommands)
			{
				$response = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/form-submit/Reboot" -ContentType "application/x-www-form-urlencoded" -WebSession $session -Method POST -Headers @{'anti-csrf-token'="$csrf2"} -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0" -SkipCertificateCheck
			}
			else
			{
				$response = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/form-submit/Reboot" -ContentType "application/x-www-form-urlencoded" -WebSession $session -Method POST -Headers @{'anti-csrf-token'="$csrf2"} -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0"
			}
		}
		else
		{
			if($DotNetCoreCommands)
			{
				$response = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/form-submit/Reboot" -ContentType "application/x-www-form-urlencoded" -WebSession $session -Method POST -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0" -SkipCertificateCheck
			}
			else
			{
				$response = Invoke-WebRequest -Uri "${http}${ClientIP}:${ClientPort}/form-submit/Reboot" -ContentType "application/x-www-form-urlencoded" -WebSession $session -Method POST -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0"
			}
		}
		
		Write-Verbose "RESPONSE: `"$response`""
			
		if($response.StatusCode -eq 200 -and !($response.Content -imatch "INVALID_LOGIN"))
		{
				$returnObject = [pscustomobject]@{'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = ""; 'Version' = ""; 'Result'="Reboot was successful"}
			
				Write-Host
				Write-Host "-------------------------------------------------" -foreground green
				Write-Host "IP Address: $ClientIP" -foreground green
				Write-Host "MAC Address: $MACAddress" -foreground green
				Write-Host "Reboot was successful." -foreground green
				Write-Host "-------------------------------------------------" -foreground green
				Write-Host
				return $returnObject
		}
		else
		{
			if(($r.Content -imatch "INVALID_LOGIN"))
			{
				$returnObject = [pscustomobject]@{ 'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = ""; 'Version' = ""; 'Result'="ERROR: Device password is incorrect"}
				
				Write-Host "ERROR: Device password is incorrect. Please use correct password for device ${ClientIP}" -foreground "red"
				return $returnObject
			}
			else
			{
				$returnObject = [pscustomobject]@{ 'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = ""; 'Version' = ""; 'Result'="ERROR: Unable to connect to device"}
				
				Write-Host "ERROR: Unable to connect to ${ClientIP}." -foreground "red"
				return $returnObject			
			}			
		}
	}
	else
	{
		if(($r.Content -imatch "INVALID_LOGIN"))
		{
			$returnObject = [pscustomobject]@{ 'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = ""; 'Version' = ""; 'Result'="ERROR: Reboot failed."}
			
			Write-Host "ERROR: Device password is incorrect. Please use correct password for device ${ClientIP}" -foreground "red"
			return $returnObject
		}
		else
		{
			$returnObject = [pscustomobject]@{ 'IPAddress' = "$ClientIP"; 'Model' = ""; 'MACAddress' = ""; 'Version' = ""; 'Result'="ERROR: Unable to connect to device"}
			
			Write-Host "ERROR: Unable to connect to ${ClientIP}." -foreground "red"
			return $returnObject			
		}
	}
}


if($OpenUI) #LOAD UI START
{
# Activate the form ============================================================
$objForm.Add_Shown({$objForm.Activate()})
[void] $objForm.ShowDialog()	
} #LOAD UI END



#Execute command from the command line input
if($Command.ToLower() -eq "signin")
{
	Write-Host "INFO: Executing signin" -foreground "Yellow"
	if($script:IPRanges.count -ne 0)
	{
		SignInPhones $script:IPRanges
	}
	else
	{
		Write-Host "ERROR: No DeviceIPRange flag provided." -foreground "red"
	}
	
}
elseif($Command.ToLower() -eq "signout")
{
	Write-Host "INFO: Executing signout" -foreground "Yellow"
	if($script:IPRanges.count -ne 0)
	{
		SignOutPhones $script:IPRanges
	}
	else
	{
		Write-Host "ERROR: No DeviceIPRange flag provided." -foreground "red"
	}
}
elseif($Command.ToLower() -eq "status")
{
	Write-Host "INFO: Executing status" -foreground "Yellow"
	if($script:IPRanges.count -ne 0)
	{
		GetStatusPhones $script:IPRanges
	}
	else
	{
		Write-Host "ERROR: No DeviceIPRange flag provided." -foreground "red"
	}
}
elseif($Command.ToLower() -eq "provision")
{
	Write-Host "INFO: Executing provision" -foreground "Yellow"
	if($script:IPRanges.count -ne 0)
	{
		ProvisionPhones $script:IPRanges
	}
	else
	{
		Write-Host "ERROR: No DeviceIPRange flag provided." -foreground "red"
	}
}
elseif($Command.ToLower() -eq "changepassword")
{
	Write-Host "INFO: Executing changepassword" -foreground "Yellow"
	if($script:IPRanges.count -ne 0 -and $script:NewPassword -ne "" -and $script:NewPassword -ne $null)
	{
		ChangeDevicePassword $script:IPRanges $script:NewPassword
	}
	else
	{
		Write-Host "ERROR: No DeviceIPRange or DeviceNewPassword flags provided." -foreground "red"
	}
}
elseif($Command.ToLower() -eq "restart")
{
	Write-Host "INFO: Executing changepassword" -foreground "Yellow"
	if($script:IPRanges.count -ne 0)
	{
		RebootPhones $script:IPRanges
	}
	else
	{
		Write-Host "ERROR: No DeviceIPRange flag provided." -foreground "red"
	}
}

# SIG # Begin signature block
# MIIZlgYJKoZIhvcNAQcCoIIZhzCCGYMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUGb6LW6ED3w/19G989SRkBDVs
# CTqgghSkMIIE/jCCA+agAwIBAgIQDUJK4L46iP9gQCHOFADw3TANBgkqhkiG9w0B
# AQsFADByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFz
# c3VyZWQgSUQgVGltZXN0YW1waW5nIENBMB4XDTIxMDEwMTAwMDAwMFoXDTMxMDEw
# NjAwMDAwMFowSDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MSAwHgYDVQQDExdEaWdpQ2VydCBUaW1lc3RhbXAgMjAyMTCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAMLmYYRnxYr1DQikRcpja1HXOhFCvQp1dU2UtAxQ
# tSYQ/h3Ib5FrDJbnGlxI70Tlv5thzRWRYlq4/2cLnGP9NmqB+in43Stwhd4CGPN4
# bbx9+cdtCT2+anaH6Yq9+IRdHnbJ5MZ2djpT0dHTWjaPxqPhLxs6t2HWc+xObTOK
# fF1FLUuxUOZBOjdWhtyTI433UCXoZObd048vV7WHIOsOjizVI9r0TXhG4wODMSlK
# XAwxikqMiMX3MFr5FK8VX2xDSQn9JiNT9o1j6BqrW7EdMMKbaYK02/xWVLwfoYer
# vnpbCiAvSwnJlaeNsvrWY4tOpXIc7p96AXP4Gdb+DUmEvQECAwEAAaOCAbgwggG0
# MA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsG
# AQUFBwMIMEEGA1UdIAQ6MDgwNgYJYIZIAYb9bAcBMCkwJwYIKwYBBQUHAgEWG2h0
# dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAfBgNVHSMEGDAWgBT0tuEgHf4prtLk
# YaWyoiWyyBc1bjAdBgNVHQ4EFgQUNkSGjqS6sGa+vCgtHUQ23eNqerwwcQYDVR0f
# BGowaDAyoDCgLoYsaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL3NoYTItYXNzdXJl
# ZC10cy5jcmwwMqAwoC6GLGh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9zaGEyLWFz
# c3VyZWQtdHMuY3JsMIGFBggrBgEFBQcBAQR5MHcwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBPBggrBgEFBQcwAoZDaHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0U0hBMkFzc3VyZWRJRFRpbWVzdGFtcGluZ0NB
# LmNydDANBgkqhkiG9w0BAQsFAAOCAQEASBzctemaI7znGucgDo5nRv1CclF0CiNH
# o6uS0iXEcFm+FKDlJ4GlTRQVGQd58NEEw4bZO73+RAJmTe1ppA/2uHDPYuj1UUp4
# eTZ6J7fz51Kfk6ftQ55757TdQSKJ+4eiRgNO/PT+t2R3Y18jUmmDgvoaU+2QzI2h
# F3MN9PNlOXBL85zWenvaDLw9MtAby/Vh/HUIAHa8gQ74wOFcz8QRcucbZEnYIpp1
# FUL1LTI4gdr0YKK6tFL7XOBhJCVPst/JKahzQ1HavWPWH1ub9y4bTxMd90oNcX6X
# t/Q/hOvB46NJofrOp79Wz7pZdmGJX36ntI5nePk2mOHLKNpbh6aKLzCCBTAwggQY
# oAMCAQICEAQJGBtf1btmdVNDtW+VUAgwDQYJKoZIhvcNAQELBQAwZTELMAkGA1UE
# BhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2lj
# ZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4X
# DTEzMTAyMjEyMDAwMFoXDTI4MTAyMjEyMDAwMFowcjELMAkGA1UEBhMCVVMxFTAT
# BgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEx
# MC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIENvZGUgU2lnbmluZyBD
# QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPjTsxx/DhGvZ3cH0wsx
# SRnP0PtFmbE620T1f+Wondsy13Hqdp0FLreP+pJDwKX5idQ3Gde2qvCchqXYJawO
# eSg6funRZ9PG+yknx9N7I5TkkSOWkHeC+aGEI2YSVDNQdLEoJrskacLCUvIUZ4qJ
# RdQtoaPpiCwgla4cSocI3wz14k1gGL6qxLKucDFmM3E+rHCiq85/6XzLkqHlOzEc
# z+ryCuRXu0q16XTmK/5sy350OTYNkO/ktU6kqepqCquE86xnTrXE94zRICUj6whk
# PlKWwfIPEvTFjg/BougsUfdzvL2FsWKDc0GCB+Q4i2pzINAPZHM8np+mM6n9Gd8l
# k9ECAwEAAaOCAc0wggHJMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQD
# AgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHkGCCsGAQUFBwEBBG0wazAkBggrBgEF
# BQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRw
# Oi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0Eu
# Y3J0MIGBBgNVHR8EejB4MDqgOKA2hjRodHRwOi8vY3JsNC5kaWdpY2VydC5jb20v
# RGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMDqgOKA2hjRodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsME8GA1UdIARI
# MEYwOAYKYIZIAYb9bAACBDAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdp
# Y2VydC5jb20vQ1BTMAoGCGCGSAGG/WwDMB0GA1UdDgQWBBRaxLl7KgqjpepxA8Bg
# +S32ZXUOWDAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzANBgkqhkiG
# 9w0BAQsFAAOCAQEAPuwNWiSz8yLRFcgsfCUpdqgdXRwtOhrE7zBh134LYP3DPQ/E
# r4v97yrfIFU3sOH20ZJ1D1G0bqWOWuJeJIFOEKTuP3GOYw4TS63XX0R58zYUBor3
# nEZOXP+QsRsHDpEV+7qvtVHCjSSuJMbHJyqhKSgaOnEoAjwukaPAJRHinBRHoXpo
# aK+bp1wgXNlxsQyPu6j4xRJon89Ay0BEpRPw5mQMJQhCMrI2iiQC/i9yfhzXSUWW
# 6Fkd6fp0ZGuy62ZD2rOwjNXpDd32ASDOmTFjPQgaGLOBm0/GkxAG/AeB+ova+YJJ
# 92JuoVP6EpQYhS6SkepobEQysmah5xikmmRR7zCCBTEwggQZoAMCAQICEAqhJdbW
# Mht+QeQF2jaXwhUwDQYJKoZIhvcNAQELBQAwZTELMAkGA1UEBhMCVVMxFTATBgNV
# BAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIG
# A1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTE2MDEwNzEyMDAw
# MFoXDTMxMDEwNzEyMDAwMFowcjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lD
# ZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UEAxMoRGln
# aUNlcnQgU0hBMiBBc3N1cmVkIElEIFRpbWVzdGFtcGluZyBDQTCCASIwDQYJKoZI
# hvcNAQEBBQADggEPADCCAQoCggEBAL3QMu5LzY9/3am6gpnFOVQoV7YjSsQOB0Uz
# URB90Pl9TWh+57ag9I2ziOSXv2MhkJi/E7xX08PhfgjWahQAOPcuHjvuzKb2Mln+
# X2U/4Jvr40ZHBhpVfgsnfsCi9aDg3iI/Dv9+lfvzo7oiPhisEeTwmQNtO4V8CdPu
# XciaC1TjqAlxa+DPIhAPdc9xck4Krd9AOly3UeGheRTGTSQjMF287DxgaqwvB8z9
# 8OpH2YhQXv1mblZhJymJhFHmgudGUP2UKiyn5HU+upgPhH+fMRTWrdXyZMt7HgXQ
# hBlyF/EXBu89zdZN7wZC/aJTKk+FHcQdPK/P2qwQ9d2srOlW/5MCAwEAAaOCAc4w
# ggHKMB0GA1UdDgQWBBT0tuEgHf4prtLkYaWyoiWyyBc1bjAfBgNVHSMEGDAWgBRF
# 66Kv9JLLgjEtUYunpyGd823IDzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB
# /wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB5BggrBgEFBQcBAQRtMGswJAYI
# KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3
# aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9v
# dENBLmNydDCBgQYDVR0fBHoweDA6oDigNoY0aHR0cDovL2NybDQuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDA6oDigNoY0aHR0cDovL2Ny
# bDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDBQBgNV
# HSAESTBHMDgGCmCGSAGG/WwAAgQwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cu
# ZGlnaWNlcnQuY29tL0NQUzALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggEB
# AHGVEulRh1Zpze/d2nyqY3qzeM8GN0CE70uEv8rPAwL9xafDDiBCLK938ysfDCFa
# KrcFNB1qrpn4J6JmvwmqYN92pDqTD/iy0dh8GWLoXoIlHsS6HHssIeLWWywUNUME
# aLLbdQLgcseY1jxk5R9IEBhfiThhTWJGJIdjjJFSLK8pieV4H9YLFKWA1xJHcLN1
# 1ZOFk362kmf7U2GJqPVrlsD0WGkNfMgBsbkodbeZY4UijGHKeZR+WfyMD+NvtQEm
# tmyl7odRIeRYYJu6DC0rbaLEfrvEJStHAgh8Sa4TtuF8QkIoxhhWz0E0tmZdtnR7
# 9VYzIi8iNrJLokqV2PWmjlIwggU1MIIEHaADAgECAhAKNIchv70WQdoZqmZoB0Fg
# MA0GCSqGSIb3DQEBCwUAMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNVBAMTKERpZ2lD
# ZXJ0IFNIQTIgQXNzdXJlZCBJRCBDb2RlIFNpZ25pbmcgQ0EwHhcNMjAwMTA2MDAw
# MDAwWhcNMjMwMTEwMTIwMDAwWjByMQswCQYDVQQGEwJBVTEMMAoGA1UECBMDVklD
# MRAwDgYDVQQHEwdNaXRjaGFtMRUwEwYDVQQKEwxKYW1lcyBDdXNzZW4xFTATBgNV
# BAsTDEphbWVzIEN1c3NlbjEVMBMGA1UEAxMMSmFtZXMgQ3Vzc2VuMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzerRQ8lBU+cD9jWzQV7i2saGNzXrXzaN
# kEUkUdZbem54qullpGQwp6Bb0hzEFsPIaPSd796kIvvQCdb2W6VM9zp5ZxZj8dIh
# 539for2NW7Av8kjj+qpq+geD7BGWhLXKdMRdfdVZgf9hgWi+FOv+bJHp5MCKi9pN
# WEi8mgvaRZd2FuGJ7+RlYpYhGamYNw9KaV32/T9t2Mm7b9As1jlss+/Zja+Jsb5R
# pDFfhSX5eKG1Fy8T0QnaEvJm0Ljr2KD2E9AAmB96ZalNuwhqPociEUflTUyrmSlY
# w9HxFZ6cWXvHidcXnFW9exHpasXC2agwxYzYs+FqobL6cDw258kidQIDAQABo4IB
# xTCCAcEwHwYDVR0jBBgwFoAUWsS5eyoKo6XqcQPAYPkt9mV1DlgwHQYDVR0OBBYE
# FP58C0FrWPjmUX3IhXKbtjOP8UHQMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAK
# BggrBgEFBQcDAzB3BgNVHR8EcDBuMDWgM6Axhi9odHRwOi8vY3JsMy5kaWdpY2Vy
# dC5jb20vc2hhMi1hc3N1cmVkLWNzLWcxLmNybDA1oDOgMYYvaHR0cDovL2NybDQu
# ZGlnaWNlcnQuY29tL3NoYTItYXNzdXJlZC1jcy1nMS5jcmwwTAYDVR0gBEUwQzA3
# BglghkgBhv1sAwEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQu
# Y29tL0NQUzAIBgZngQwBBAEwgYQGCCsGAQUFBwEBBHgwdjAkBggrBgEFBQcwAYYY
# aHR0cDovL29jc3AuZGlnaWNlcnQuY29tME4GCCsGAQUFBzAChkJodHRwOi8vY2Fj
# ZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRTSEEyQXNzdXJlZElEQ29kZVNpZ25p
# bmdDQS5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAfBTJIJek
# j0gumY4Ej7cbSHLnbMh0hrDXrAaUxFadLJgKMCl8N0YOuR/5Vw4voCvgWuFv1dVO
# ns7lZzu/Y9T/kPqNpxVzxLO6jZDN3zEPmpt2E1nqelL3BdBF0eEK8i8mEkrFdi8Q
# gT1VhqjeROCLKUm8N928wM3iBEjH9pFyQlBDNHFgiFt9H/NXhFJ5IfC8yDzbt7a/
# 9hVwtcWMWygxvSKjL6pCTAXBXPWajiU+ddcV6VRs3QuRYsex0DGrABM1AcDXnRKZ
# OlLu2bhh7abbeWBWXCAaBHYmCFbPpspUj6eb5R8AI52+leeMEggPIw1SX21HHh6j
# rHLF9RJUBJDeSzGCBFwwggRYAgEBMIGGMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNV
# BAMTKERpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBDb2RlIFNpZ25pbmcgQ0ECEAo0
# hyG/vRZB2hmqZmgHQWAwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwxCjAIoAKA
# AKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFFLK6YbydKgnztrlbM/X8ee4
# WB36MA0GCSqGSIb3DQEBAQUABIIBADcXOWMgfXTnbmf/TKjsSIJSl3+a0RqRADFO
# E9u3wqZ9MjlZRH2rLwaQV9MsHttOOJTl/rWiqeqXW1HHnbirGMut14LqIa1Hxl8r
# Q53bliWo2lEpB5qoHC7qAg4kg6Bmwc/IkORVf51g33Sf8g0Ie0UWbE+tBxJ7iTs/
# gNb8OyFk78j7Sr1q2hmCvpwcZuNI+0J3J1xTW2we3bqbf4SX6MJRPslB5KxVNAft
# yqSBDJ8ujLheRHe8o+EjtPpji3cRSUTupDYz/KNj7VxXp81b6DtSwLxGpC2PY9dx
# Fr6jeLnoWFW4bAOcO6h1+lVQ8bU/SEJSk3Tq44cbaRux8cpVD92hggIwMIICLAYJ
# KoZIhvcNAQkGMYICHTCCAhkCAQEwgYYwcjELMAkGA1UEBhMCVVMxFTATBgNVBAoT
# DERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UE
# AxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIFRpbWVzdGFtcGluZyBDQQIQDUJK
# 4L46iP9gQCHOFADw3TANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkq
# hkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIyMDIxMjEyMTE1OVowLwYJKoZIhvcN
# AQkEMSIEIKNsye9P6gZCOZME/+zaWOGN85bXEU76dwWXdmRYXXPhMA0GCSqGSIb3
# DQEBAQUABIIBACAfEXq6eHCdHtcXgbhCYquVGulp3UNrsvjCT7OxcYf9zU+wsxbP
# 1bzRBjqHDD+sGhioOUCHrXQyfo79uhMLKbos8Qq2M6hhICyViF9Ak3WE2WsEhwyb
# DvCkqtaP9Aqr5tlEinB+sOo55itSKH44usiHeK8Rj93ut52392kDJ916sw+2QxRX
# AmaF1kD3vLmahFth2wmHIgJeP5Wt6AZ9n2CwNIootRTlRDfirXzrUod2AbGil/J1
# 9z+kMIUMOMq7MOjzZMS3UAy2Jers1F0I60PHVyY/oBBIwnkPGZ3bGtErAJ1/QqsG
# pzdKFG9enJCCVOBn6KkKvwFbO/KfpnOpgRY=
# SIG # End signature block
