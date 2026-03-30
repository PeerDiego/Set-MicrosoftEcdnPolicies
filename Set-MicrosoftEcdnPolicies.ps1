<#
.SYNOPSIS
This script configures a Windows computer with required Microsoft eCDN browser policies.

.DESCRIPTION
This script adds registry keys to a Windows computer for configuring Microsoft eCDN on the following browsers:
    - Microsoft Edge
    - Google Chrome
    - Mozilla Firefox (WebRTC only; Firefox has not yet shipped Local Network Access restrictions)

The following browser policies are configured:
    1. WebRtcLocalIpsAllowedUrls
       Disables WebRTC IP obfuscation/mDNS for eCDN domains, so the eCDN client can discover the
       viewer's real IP address for peer-to-peer connectivity.
       Applies to: Microsoft Edge, Google Chrome, Mozilla Firefox

    2. LocalNetworkAccessAllowedForUrls
       Allows eCDN domains to request access to local network resources, enabling peer-to-peer
       connections within organizational networks.
       Applies to: Microsoft Edge, Google Chrome

.PARAMETER eCDN_domain
The domain to add to all applicable registry keys for all policies. Default domains are applied if
not specified.

.PARAMETER Enumerated
Enumerate all eCDN domains explicitly in the registry keys instead of using wildcards (*).

.EXAMPLE
.\Set-MicrosoftEcdnPolicies.ps1
# Applies all default eCDN domains to both policies for all supported browsers.

.EXAMPLE
.\Set-MicrosoftEcdnPolicies.ps1 -eCDN_domain "https://teams.cloud.microsoft"
# Adds the specified domain to both policies for all supported browsers.

.EXAMPLE
.\Set-MicrosoftEcdnPolicies.ps1 -Enumerated
# Enumerates all eCDN subdomains explicitly instead of using wildcards.

.NOTES
Must be run as an Administrator.
Combines Disable-mDNS-for-eCDN.ps1 and Enable-LNA-for-eCDN.ps1 into a single script.
As of May 22nd 2025, the upcoming .cloud.microsoft domain migration targets are included.
At some point in the future, the old domains will be deprecated.
Author: Diego Reategui | Github username: PeerDiego

.OUTPUTS
None

.INPUTS
None

.LINK
https://learn.microsoft.com/ecdn/how-to/disable-mdns
https://learn.microsoft.com/ecdn/how-to/configure-local-network-access-policy
#>
[cmdletbinding(DefaultParameterSetName = "Default", SupportsShouldProcess)]
param(
    [Parameter(
        Mandatory = $false,
        ParameterSetName = "Default",
        HelpMessage = "Specify an eCDN domain to add to all applicable registry keys. Default domains are applied if omitted.")]
    [string]
    $eCDN_domain,

    [Parameter(
        ParameterSetName = "Add all",
        HelpMessage = "Enumerate all eCDN domains explicitly in the registry keys instead of using a wildcard (*).")]
    [switch]
    $Enumerated = $false
)

if (-not [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")) {
    Write-Host "This script must be run as an Administrator" -ForegroundColor Red
    return
}

$HKLM_SW_Policies_Path = "HKLM:\SOFTWARE\Policies"

# Each policy defines:
#   name               - the registry key name for the policy
#   action_description - used in status messages
#   browsers           - the browsers that support this policy, each with:
#                          name       - display name (also used to derive registry path: Company\Name)
#                          executable - used to look up the install path in App Paths
#                          reg_key    - the registry subkey to create values under
#   domains            - the domain sets: Default (wildcards), Enumerated (explicit), Constant (always applied)
#
# NOTE: Domain wildcard format differs per policy:
#   WebRtcLocalIpsAllowedUrls        uses *.  wildcards
#   LocalNetworkAccessAllowedForUrls uses [*.] wildcards
#
# NOTE: Firefox uses a special registry structure for WebRTC (Preferences key, comma-separated value).
#       Firefox is not yet included in LocalNetworkAccessAllowedForUrls as it hasn't shipped LNA
#       restrictions to its release channel.

$policy_list = @(
    @{
        name               = "WebRtcLocalIpsAllowedUrls"
        action_description = "disable mDNS's local IP obfuscation"
        browsers           = @(
            @{ name = "Microsoft Edge";  executable = "msedge.exe";  reg_key = "WebRtcLocalIpsAllowedUrls" },
            @{ name = "Google Chrome";   executable = "chrome.exe";  reg_key = "WebRtcLocalIpsAllowedUrls" },
            @{ name = "Mozilla Firefox"; executable = "firefox.exe"; reg_key = "Preferences" }
        )
        domains            = @{
            Default    = @("*.ecdn.teams.microsoft.com", "*.ecdn.teams.cloud.microsoft")
            Enumerated = @(
                "https://sdk.ecdn.teams.microsoft.com",
                "https://sdk.ecdn.teams.cloud.microsoft",
                "https://sdk.msit.ecdn.teams.microsoft.com",
                "https://sdk.msit.ecdn.teams.cloud.microsoft"
            )
            Constant   = @("https://teams.microsoft.com", "https://teams.cloud.microsoft")
        }
    },
    @{
        name               = "LocalNetworkAccessAllowedForUrls"
        action_description = "enable Local Network Access"
        browsers           = @(
            @{ name = "Microsoft Edge"; executable = "msedge.exe"; reg_key = "LocalNetworkAccessAllowedForUrls" },
            @{ name = "Google Chrome";  executable = "chrome.exe"; reg_key = "LocalNetworkAccessAllowedForUrls" }
            # Firefox not yet included: Firefox hasn't shipped Local Network Access restrictions to its release channel.
        )
        domains            = @{
            Default    = @("[*.]ecdn.teams.microsoft.com", "[*.]ecdn.teams.cloud.microsoft")
            Enumerated = @(
                "https://sdk.ecdn.teams.microsoft.com",
                "https://sdk.ecdn.teams.cloud.microsoft",
                "https://sdk.msit.ecdn.teams.microsoft.com",
                "https://sdk.msit.ecdn.teams.cloud.microsoft"
            )
            Constant   = @("https://teams.microsoft.com", "https://teams.cloud.microsoft", "https://engage.cloud.microsoft/")
        }
    }
)


function _create_RegKey_if_not_exists($key_path) {
    $key = Get-Item -Path $key_path -ErrorAction SilentlyContinue
    if (!$key) {
        New-Item -Path $key_path -ErrorAction SilentlyContinue -Force | Out-Null
        Write-Verbose "    Created key: $key_path"
    }
    else {
        # Write-Verbose "    Key already exists: $key_path"
    }
}


function Add-EcdnPolicyUrl {
    [CmdletBinding(SupportsShouldProcess)]
    <#
    .SYNOPSIS
    Adds a single URL to a browser's eCDN policy registry key.
    .DESCRIPTION
    Creates the required registry path under HKLM:\SOFTWARE\Policies and writes the URL as a new value.
    Browser installation must be verified by the caller.
    .OUTPUTS
    [string] 'added', 'existed', or 'failed'
    .PARAMETER URL
    The domain or URL to add to the policy registry key.
    .PARAMETER Browser
    Hashtable with keys: name, executable, reg_key. Determines the registry path and storage format.
    .PARAMETER ActionDescription
    Short phrase used in Verbose messages to describe the policy action (e.g. "disable mDNS").
    #>
    param (
        [Parameter(Mandatory = $true, HelpMessage = "URL to add to the policy list")]
        [string] $URL,

        [Parameter(Mandatory = $true, HelpMessage = "Browser hashtable (name, executable, reg_key)")]
        $Browser,

        [Parameter(Mandatory = $true, HelpMessage = "Short description of the policy action for status messages")]
        [string] $ActionDescription
    )

    Write-Verbose "      > $URL"

    # Derive registry path from browser name: "Microsoft Edge" -> Policies\Microsoft\Edge
    $Browser_Company, $Browser_Name = $Browser.name.Split()
    $Company_KeyPath = Join-Path $HKLM_SW_Policies_Path $Browser_Company
    $Browser_KeyPath = Join-Path $Company_KeyPath $Browser_Name
    $Policy_KeyPath  = Join-Path $Browser_KeyPath $Browser.reg_key

    _create_RegKey_if_not_exists $Company_KeyPath
    _create_RegKey_if_not_exists $Browser_KeyPath
    _create_RegKey_if_not_exists $Policy_KeyPath

    $PolicyRegKey = Get-Item -Path $Policy_KeyPath -ErrorAction SilentlyContinue
    if (!$PolicyRegKey) {
        Write-Verbose "      Failed to create key(s) >_>"
        return 'failed'
    }

    $value_names = $PolicyRegKey.GetValueNames()

    # Check whether the URL already exists as a standalone registry value
    foreach ($value_name in $value_names) {
        $value = $PolicyRegKey.GetValue($value_name)
        # Write-Verbose "      Found $($PolicyRegKey.GetValueKind($value_name)) '$value_name' = '$value'"
        if ($value -eq $URL) {
            Write-Verbose "      Already exists in $($PolicyRegKey.GetValueKind($value_name)) '$value_name'"
            return 'existed'
        }
    }

    # Firefox WebRTC stores all domains as a single comma-separated string under Preferences
    if ($Browser.reg_key -eq "Preferences") {
        $value_name = 'media.peerconnection.ice.obfuscate_host_addresses.blocklist'
        $existing = $PolicyRegKey.GetValue($value_name)
        if ($existing) {
            $existing_values = $existing.Split(",").foreach({ $_.Trim() })
            if ($existing_values -contains $URL) {
                Write-Verbose "      Already exists in '$value_name'"
                return 'existed'
            }
            $URL = ($existing_values + $URL) -join ", "
        }
    }
    else {
        # For Chromium-based browsers, domains are stored as individually numbered string values
        $value_name = $value_names.Count + 1
        while ($value_name -in $value_names) {
            $value_name++
        }
    }

    if ($PSCmdlet.ShouldProcess($Policy_KeyPath, "Set value '$value_name' = '$URL'")) {
        try {
            New-ItemProperty -Path $Policy_KeyPath -Name $value_name -PropertyType String -Value $URL -ErrorAction Stop -Force | Out-Null
            Write-Verbose "      Value '$value_name' written"
        }
        catch {
            Write-Verbose "      Failed to write value: $_"
            return 'failed'
        }
    }
    return 'added'
}


# Build the master browser list (unique browsers in policy order)
$all_browsers = [System.Collections.Generic.List[hashtable]]::new()
$seen_executables = [System.Collections.Generic.HashSet[string]]::new()
foreach ($policy in $policy_list) {
    foreach ($b in $policy.browsers) {
        if ($seen_executables.Add($b.executable)) {
            $all_browsers.Add(@{ name = $b.name; executable = $b.executable })
        }
    }
}

# Main loop order: Browser > Policy > URL
foreach ($browser_info in $all_browsers) {

    Write-Host "`n=== $($browser_info.name) ===" -ForegroundColor Cyan

    # Check installation once per browser
    $browser_path = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$($browser_info.executable)" -ErrorAction SilentlyContinue).'(Default)'
    if (-not $browser_path) {
        Write-Host "  not found" -BackgroundColor DarkGray -ForegroundColor Black
        continue
    }

    $browser_version = (Get-Item -Path $browser_path -ErrorAction SilentlyContinue).VersionInfo
    if ($browser_version) {
        Write-Verbose "  Installed at '$browser_path'"
        Write-Host "  v.$($browser_version.FileVersion)" -ForegroundColor DarkGray
    }
    else {
        Write-Host "  Installed but unable to determine version info" -BackgroundColor Red -ForegroundColor White
    }

    foreach ($policy in $policy_list) {

        # Skip policies that don't apply to this browser
        $browser_policy = $policy.browsers | Where-Object { $_.executable -eq $browser_info.executable }
        if (-not $browser_policy) {
            Write-Verbose "  $($policy.name): not applicable for $($browser_info.name)"
            continue
        }

        $domains_to_add = if ($eCDN_domain) {
            @($eCDN_domain)
        }
        elseif ($Enumerated) {
            $policy.domains["Constant"] + $policy.domains["Enumerated"]
        }
        else {
            $policy.domains["Constant"] + $policy.domains["Default"]
        }

        Write-Verbose "    -- $($policy.name) --"

        $counts = @{ added = 0; existed = 0; failed = 0 }
        foreach ($domain in $domains_to_add) {
            $result = Add-EcdnPolicyUrl -URL $domain -Browser $browser_policy -ActionDescription $policy.action_description
            $counts[$result]++
        }

        # Per-policy summary line
        $parts = @()
        if ($counts['added']   -gt 0) { $parts += "$($counts['added']) added" }
        if ($counts['existed'] -gt 0) { $parts += "$($counts['existed']) already existed" }
        if ($counts['failed']  -gt 0) { $parts += "$($counts['failed']) failed" }
        $color = if ($counts['failed'] -gt 0) { 'Red' } elseif ($counts['added'] -gt 0) { 'Green' } else { 'DarkGreen' }
        Write-Host "  $($policy.name): $($parts -join ', ')" -ForegroundColor $color
    }
}

Write-Host ""
