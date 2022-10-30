#Requires -Modules AutomatedLab
#Requires -RunAsAdministrator
#Requires -PSEdition Core

param (
    [Parameter(Mandatory)]
    [String]$DomainName,
    [Parameter(Mandatory)]
    [String]$LabName,
    [Parameter()]
    [switch]$NoGUI,
    [Parameter()]
    [switch]$RouterGUI,
    [Parameter()]
    $RAM = 2GB,
    [Parameter()]
    [switch]$Office,
    [Parameter(Mandatory)]
    [string]$OUName,
    [Parameter(Mandatory)]
    [string]$AdminUserName,
    [Parameter()]
    [switch]$MockUsers
)

[String]$ISOStore = "C:\LabSources\ISOs"

function New-Lab {
    [Int]$MainInterfaceIndex = (Get-NetRoute -DestinationPrefix '0.0.0.0/0', '::/0' | Sort-Object -Property { $_.InterfaceMetric + $_.RouteMetric } -Top 1).ifIndex
    [String]$MainInterface = Get-NetAdapter | Where-Object { $_.ifIndex -eq $MainInterfaceIndex } | Select-Object -ExpandProperty Name

    New-Item -ItemType Directory C:\AutomatedLab-VMs -ErrorAction SilentlyContinue
    New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV -VmPath "C:\AutomatedLab-VMs"
    Add-LabVirtualNetworkDefinition -Name $LabName
    Add-LabVirtualNetworkDefinition -Name 'Default Switch' -HyperVProperties @{ SwitchType = 'External'; AdapterName = $MainInterface }
}

function Add-LabVMs {
    [String]$ServerEdition = if ( $NoGUI ) { "Windows Server 2019 Datacenter" } else { "Windows Server 2019 Datacenter (Desktop Experience)" }
    [String]$Router_ServerEdition = if ( $RouterGUI ) { "Windows Server 2019 Datacenter (Desktop Experience)" } else { "Windows Server 2019 Datacenter" }

    # Declare main Root DC
    Add-LabMachineDefinition -Name DC1 -Memory $RAM -OperatingSystem $ServerEdition -Roles RootDC -DomainName $DomainName -Network $LabName
    # Enable Internet Access
    $netAdapter = @()
    $netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName
    $netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp
    Add-LabMachineDefinition -Name Router1 -Memory 4GB -OperatingSystem $Router_ServerEdition -Roles Routing -NetworkAdapter $netAdapter -DomainName $DomainName

    # Declare Client Machines
    if ($Office) {
        Add-LabIsoImageDefinition -Name Office2016 -Path $ISOStore\ProPlusRetail.iso
        Add-LabMachineDefinition -Name Client1 -Memory $RAM -OperatingSystem 'Windows 10 Education' -DomainName $DomainName -Network $LabName -Roles Office2016
        Add-LabMachineDefinition -Name Client2 -Memory $RAM -OperatingSystem 'Windows 10 Education' -DomainName $DomainName -Network $LabName -Roles Office2016
    }
    else {
        Add-LabMachineDefinition -Name Client1 -Memory $RAM -OperatingSystem 'Windows 10 Education' -DomainName $DomainName -Network $LabName
        Add-LabMachineDefinition -Name Client2 -Memory $RAM -OperatingSystem 'Windows 10 Education' -DomainName $DomainName -Network $LabName
    }
}

function Add-LabDefaultOU {
    # Create initial root OrganisationalUnit
    [String]$DCPath = 'DC={0}' -f ($DomainName.ToUpper() -replace '\.', ', DC=')
    Invoke-LabCommand -ScriptBlock {
        New-ADOrganizationalUnit -Name $OUName -Path $DCPath
    } -ComputerName DC1 -Variable (Get-Variable -Name OUName), (Get-Variable -Name OUPath) -PassThru
}

function Add-LabDefaultAdministrator {
    # Create Administrator account outside of the default Administrator account
    Write-Host "Creating main AD account"
    [String]$DCPath = 'DC={0}' -f ($DomainName.ToUpper() -replace '\.', ', DC=')
    Invoke-LabCommand -ScriptBlock {
        New-ADUser -Name "Clark Kent" `
            -GivenName "Clark" `
            -Surname "Kent" `
            -SamAccountName $AdminUserName `
            -UserPrincipalName ($AdminUserName + "@" + $DomainName) `
            -AccountPassword (ConvertTo-SecureString "9sk25qtOjQMaEe4kIMBabWS44oCFSHDwfhyiAkbykuM" -AsPlainText -Force) `
            -Company "Test124" `
            -Title "CEO" `
            -Country "FR" `
            -Description "Test Account Creation" `
            -DisplayName "Test Admin" `
            -PostalCode "75000" `
            -Path ( "OU=" + $OUName + "," + $DCPath ) `
            -Enabled $true
    } -Variable (Get-Variable -Name AdminUserName) -ComputerName DC1 -PassThru
}


function Add-LabMockOUs {
    # Create nested OUs for testing
    $import_mockOUs = Import-Csv -Path .\MockOUs.csv
    [String]$DCPath = 'DC={0}' -f ($DomainName.ToUpper() -replace '\.', ', DC=')
    [String]$RootOUPath = ('OU=' + $OUName + ',' + $DCPath)
    Invoke-LabCommand -ScriptBlock {
        $import_mockOUs | ForEach-Object {
            if ($_.RootOU -ne $OUName) {
                if ((Get-ADOrganizationalUnit -Filter *).Name -contains $_.RootOU) {
                    [String]$OUPath = ( 'OU=' + $_.RootOU + ',' + $RootOUPath )
                    New-ADOrganizationalUnit -Name $_.OUName -Path $OUPath
                }
                else {
                    Write-Warning -Message "OU named $($_.OUName) is not valid due to nesting issue"
                }
            }
            else {
                [String]$OUPath = $RootOUPath
                New-ADOrganizationalUnit -Name $_.OUName -Path $OUPath
            }
        }
    } -ComputerName DC1 -Variable (Get-Variable -Name OUName), (Get-Variable DCPath), (Get-Variable import_mockOUs), (Get-Variable RootOUPath) -PassThru
}

function Add-LabMockUsers {
    # python.exe .\csvgen.py $DomainName
    $import_mockusers = Import-Csv -Path .\UserMockList.csv
    [String]$DCPath = 'DC={0}' -f ($DomainName.ToUpper() -replace '\.', ', DC=')
    [String]$RootOUPath = ('OU=' + $OUName + ',' + $DCPath)
    Invoke-LabCommand -ScriptBlock {
        [int]$idx = 0
        [String]$OUPath = ("OU=Students," + $RootOUPath)
        $import_mockusers | ForEach-Object {
            if (($idx -ge 60) -and ($idx -lt 100)) {
                $OUPath = ("OU=Profs,OU=Employer," + $RootOUPath)
                Write-Host $idx
            }
            elseif ($idx -ge 100) {
                $OUPath = ("OU=Administrative,OU=Employer," + $RootOUPath)
                Write-Host Adm
            }
            New-ADUser -Name "$($_.FirstName + " " + $_.LastName)" `
                -GivenName $_.FirstName `
                -Surname $_.LastName `
                -UserPrincipalName $_.UserprincipalName `
                -SamAccountName $_.SamAccountName `
                -AccountPassword (ConvertTo-SecureString ($_.AccountPassword) -AsPlainText -Force) `
                -EmployeeID $_.EmployeeID `
                -Company "Test124" `
                -Country $_.Country `
                -Description "Test Account Creation" `
                -PostalCode $_.PostalCode `
                -Path $OUPath `
                -ChangePasswordAtLogon $true `
                -Enabled $true `
                -PassThru `
                -WhatIf
            $idx = $idx + 1
        }
    } -Variable (Get-Variable -Name import_mockusers),(Get-Variable -Name OUName), (Get-Variable DCPath), (Get-Variable RootOUPath) -ComputerName DC1 -PassThru
}

New-Lab
Add-LabVMs
Install-Lab -ErrorAction Stop -DelayBetweenComputers 15
if ($MockData) {
    Add-LabDefaultOU
    Add-LabDefaultAdministrator
    Add-LabMockOU
    Add-LabMockUsers
}