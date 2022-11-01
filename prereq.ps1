#Requires -RunAsAdministrator
#Requires -PSEdition Core

[String]$ISOStore = "C:\LabSources\ISOs"

function Install-Prerequisites {
    Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform, HypervisorPlatform, Microsoft-Hyper-V-All -All -NoRestart
    if (-not ("NuGet" -in (Get-PackageProvider).Name)) {
        try {
            Install-PackageProvider Nuget -Force -ErrorAction Stop
        }
        catch {
            Write-Host "Caught"
            Install-NuGet -Manual
        }
    }
}

function Install-NuGet {
    param (
        [Parameter(Mandatory)]
        [switch]$Manual
    )
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-Module -Name MSOnline -Force
}

function Install-AutomatedLab {
    # Instructions from https://automatedlab.org/en/latest/Wiki/Basic/install/#
    if ("AutomatedLab" -notin (Get-Module).Name) {
        Install-Module AutomatedLab -SkipPublisherCheck -AllowClobber
        [Environment]::SetEnvironmentVariable('AUTOMATEDLAB_TELEMETRY_OPTIN', 'false', 'Machine')
        env:AUTOMATEDLAB_TELEMETRY_OPTIN = 'false'
        Enable-LabHostRemoting -Force
        New-LabSourcesFolder -DriveLetter C
    }
    else {
        if (("Education" -notin (Get-LabAvailableOperatingSystem -Path C:\LabSources).Edition) -or "ServerDatacenter" -notin (Get-LabAvailableOperatingSystem -Path C:\LabSources).Edition) {
            ;
        }
        else {
            Write-Host "You can run .\cluster.ps1 now that all the prerequisite are ready"
            Exit 0
        }
    }
    Copy-Item .\*.iso ${ISOStore}
    if (("Education" -notin (Get-LabAvailableOperatingSystem -Path C:\LabSources).Edition) -or ("ServerDatacenter" -notin (Get-LabAvailableOperatingSystem -Path C:\LabSources).Edition)) {
        Write-Error -Message "Missing editions for this script to run, please manually place the correct ISOs in ${ISOStore}" -ErrorAction Stop
    }
    else {
        Write-Host "You can run .\cluster.ps1 now that all the prerequisite are ready"
        Exit 0
    }

}