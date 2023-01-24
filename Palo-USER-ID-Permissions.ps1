<#	
	.NOTES
	===========================================================================
	 Created on:   	01/24/2023
	 Created by:    Noah Huotari
	 Organization: 	HBS
	 Filename:     	Palo-USER-ID-Permissions.ps1
	===========================================================================
	.DESCRIPTION
		Sets permissions for Palo Alto User ID in AD and WMI
        Run from one DC or from domain joined device with correct permissions
#>

#SET AD USER INFO HERE
$domain = "criterion.local"
$username = "SVC_PA-LDAP"

#dont change anything below here
$adGroups = "Distributed COM Users","Event Log Readers","Remote Management Users","Server Operators","WinRMRemoteWMIUsers__"
$fullDN = "$domain"+"\"+"$username"

#Add user to needed AD Groups
foreach ($group in $adGroups) {
    Add-ADGroupMember -Identity $group -Members $username
}

#WMI/DCOM Setup
#SID work
function get-sid
{
Param (
$DSIdentity
)
$ID = new-object System.Security.Principal.NTAccount($DSIdentity)
return $ID.Translate( [System.Security.Principal.SecurityIdentifier] ).toString()
}

#Start DCOM & WMI work
#Build permissions strings
$SDDL = "A;;CCWP;;;$sid"
$DCOMSDDL = "A;;CCDCRP;;;$sid"

$sid = get-sid $fullDN

$domainControllers = Get-ADDomainController | Select-Object Name
foreach ($dc in $domainControllers.Name)
{
    $Reg = [WMIClass]"\\$dc\root\default:StdRegProv"
    $DCOM = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","MachineLaunchRestriction").uValue
    $security = Get-WmiObject -ComputerName $dc -Namespace root/cimv2 -Class __SystemSecurity
    $converter = new-object system.management.ManagementClass Win32_SecurityDescriptorHelper
    $binarySD = @($null)
    $result = $security.PsBase.InvokeMethod("GetSD",$binarySD)
    $outsddl = $converter.BinarySDToSDDL($binarySD[0])
    $outDCOMSDDL = $converter.BinarySDToSDDL($DCOM)
    $newSDDL = $outsddl.SDDL += "(" + $SDDL + ")"
    $newDCOMSDDL = $outDCOMSDDL.SDDL += "(" + $DCOMSDDL + ")"
    $WMIbinarySD = $converter.SDDLToBinarySD($newSDDL)
    $WMIconvertedPermissions = ,$WMIbinarySD.BinarySD
    $DCOMbinarySD = $converter.SDDLToBinarySD($newDCOMSDDL)
    $DCOMconvertedPermissions = ,$DCOMbinarySD.BinarySD
    
    #Set new permissions
    $result = $security.PsBase.InvokeMethod("SetSD",$WMIconvertedPermissions)
    $result = $Reg.SetBinaryValue(2147483650,"software\microsoft\ole","MachineLaunchRestriction", $DCOMbinarySD.binarySD)
}
