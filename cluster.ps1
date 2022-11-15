#Requires -RunAsAdministrator
#Requires -PSEdition Desktop

<#
.SYNOPSIS
  Deploys a mock lab
.DESCRIPTION
  AutomatedLab-script to create a mock lab with a DC, router and 2 clients
.PARAMETER DomainName
  Name of the AD Domain to create (Mandatory)
.PARAMETER LabName
  Name of the lab (Used to create, find the lab and restore it when switching shells) (Mandatory)
.PARAMETER GUILess_DC
  Install the non-GUI version of Windows Server on the DC
.PARAMETER RouterGUI
  Install the GUI version of Windows Server on the Router
.PARAMETER RAM
  Quantity of RAM for the DC (Default: 2GB), the client and routers will use half of the mentionned capacity
.PARAMETER Office
  Installs Office 2016 on the Clients (requires the appropriate image file to be available and in the appropriate folder)
.PARAMETER MockData
  Creates mock users/OUs and groups
.PARAMETER OUName
  Name of the created mock Organisational Unit (Only applies with MockData, and MUST conform to what is in MockOUs.csv)
.PARAMETER AdminUserName
  Name of the created Domain Administrator Account (Only applies with MockData)
#>



[CmdletBinding(DefaultParametersetName = 'None')]
param(
  [Parameter(Mandatory)]
  [string]$DomainName,
  [Parameter(Mandatory)]
  [string]$LabName,
  [Parameter()]
  $RAM = 4GB,
  [Parameter()]
  [ValidateScript({ (Get-LabAvailableOperatingSystem).OperatingSystemImageName -match $_ -as [bool] })]
  [String]$ServerGen = 2019,
  [Parameter()]
  [switch]$GUILess_DC,
  [Parameter()]
  [switch]$RouterGUI,
  [Parameter()]
  [ValidateScript({ (Get-LabAvailableOperatingSystem).OperatingSystemImageName -match $_ -as [bool] })]
  [String]$ClientGen = 10,
  [Parameter()]
  [switch]$Office,
  [Parameter(ParameterSetName = 'Mock', Mandatory = $false)]
  [switch]$MockData,
    [Parameter(ParameterSetName = 'Mock', Mandatory = $true)]
    [string]$OUName = "MockUsers",
    [Parameter(ParameterSetName = 'Mock', Mandatory = $true)]
    [ValidatePattern('^(?:(?:[^. \"\/\\\[\]\:\|\\+\=\;\?\*\<\>\,][^\"\/\\\[\]\:\|\\+\=\;\?\*\<\>\,]{0,62}[^. \"\/\\\[\]\:\|\\+\=\;\?\*\<\>\,])|[^.\"\/\\\[\]\:\|\\+\=\;\?\*\<\>\,])$')]
    [string]$AdminUserName
)

[string]$ISOStore = "C:\LabSources\ISOs"

function New-Lab {
  <#
  .SYNOPSIS
    New-Lab creates the main boilerplate needed to declare the lab
  #>

  # Get the current main interface to bound the bridge
  [int]$MainInterfaceIndex = if (((Get-NetRoute -DestinationPrefix '0.0.0.0/0', '::/0' | Sort-Object -Property { $_.InterfaceMetric + $_.RouteMetric }).ifIndex | Select-Object -Unique).Count -eq 1) { ((Get-NetRoute -DestinationPrefix '0.0.0.0/0', '::/0' | Sort-Object -Property { $_.InterfaceMetric + $_.RouteMetric }).ifIndex | Select-Object -Unique) } else { (Get-NetRoute -DestinationPrefix '0.0.0.0/0', '::/0' | Sort-Object -Property { $_.InterfaceMetric + $_.RouteMetric }).ifIndex[0] }
  [string]$MainInterface = Get-NetAdapter | Where-Object { $_.ifIndex -eq $MainInterfaceIndex } | Select-Object -ExpandProperty Name

  New-Item -ItemType Directory C:\AutomatedLab-VMs -ErrorAction SilentlyContinue
  New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV -VmPath "C:\AutomatedLab-VMs"
  Add-LabVirtualNetworkDefinition -Name $LabName
  Add-LabVirtualNetworkDefinition -Name ("${LabName}_External") -HypervProperties @{ SwitchType = 'External'; AdapterName = $MainInterface }
}

function Add-LabVMs {
  <#
  .SYNOPSIS
    Define all VMs of the Lab
  #>

  $ClientMachines = @()
  $ServerMachines = @()
  [string]$ServerEdition = if ($GUILess_DC) { ("Windows Server ${ServerGen} Datacenter") } else { "Windows Server ${ServerGen} Datacenter (Desktop Experience)" }
  [string]$RouterServerEdition = if ($RouterGUI) { "Windows Server ${ServerGen} Datacenter (Desktop Experience)" } else { "Windows Server ${ServerGen} Datacenter" }
  [string]$ClientOS = ("Windows ${ClientGen} Education")

  Add-LabMachineDefinition -Name DC1 -Processors 4 -Memory $RAM -OperatingSystem $ServerEdition -Roles RootDC -DomainName $DomainName -Network $LabName
  $ServerMachines += "DC1"
  # Enable Internet Access
  $netAdapter = @()
  $netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName
  $netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch "${LabName}_External" -UseDhcp
  Add-LabMachineDefinition -Name Router1 -Memory ($RAM / 2) -OperatingSystem $RouterServerEdition -Roles Routing -NetworkAdapter $netAdapter -DomainName $DomainName
  $ServerMachines += "Router1"

  # Declare Client Machines
  # Take into account hosts with 8GB of RAM, preventing from only giving 1GB of RAM to client machines and only deploying one client machine
  $PhysicalRAMAmount = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).sum / 1gb
  $ClientRAM = if ($RAM -lt 4GB) { $RAM } else { ($RAM / 2) }
  if ($Office) {
    Add-LabIsoImageDefinition -Name Office2016 -Path $ISOStore\ProPlusRetail.iso
    Add-LabMachineDefinition -Name Client1 -Memory $ClientRAM -OperatingSystem $ClientOS -DomainName $DomainName -Network $LabName -Roles Office2016
    $ClientMachines += "Client1"
    if ($PhysicalRAMAmount -gt 15) {
      Add-LabMachineDefinition -Name Client2 -Memory $ClientRAM -OperatingSystem $ClientOS -DomainName $DomainName -Network $LabName -Roles Office2016
      $ClientMachines += "Client2"
    }
  }
  else {
    Add-LabMachineDefinition -Name Client1 -Memory $ClientRAM -OperatingSystem $ClientOS -DomainName $DomainName -Network $LabName
    $ClientMachines += "Client1"
    if ($PhysicalRAMAmount -gt 15) {
      Add-LabMachineDefinition -Name Client2 -Memory $ClientRAM -OperatingSystem $ClientOS -DomainName $DomainName -Network $LabName
      $ClientMachines += "Client2"
    }
  }
  return $ServerMachines, $ClientMachines
}

function Add-LabDefaultOU {
  <#
  .SYNOPSIS
    Create initial root OrganisationalUnit
  #>
  [string]$DCPath = 'DC={0}' -f ($DomainName.ToUpper() -replace '\.', ',DC=')
  Invoke-LabCommand -ScriptBlock {
    New-ADOrganizationalUnit -Name $OUName -Path $DCPath
  } -ComputerName DC1 -Variable (Get-Variable -Name OUName), (Get-Variable -Name DCPath) -PassThru
}

function Add-LabDefaultAdministrator {
  <#
  .SYNOPSIS
    Create Domain Administrator account outside of the default Administrator account
  #>
  Write-Host "Creating main AD account"
  [string]$DCPath = 'DC={0}' -f ($DomainName.ToUpper() -replace '\.', ',DC=')
  [string]$RootOUPath = ('OU=' + $OUName + ',' + $DCPath)
  # CHANGE THE PASSWORD
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
      -Path $RootOUPath `
      -Enabled $true
  } -Variable (Get-Variable -Name DomainName), (Get-Variable -Name AdminUserName), (Get-Variable -Name RootOUPath) -ComputerName DC1 -PassThru
}


function Add-LabMockOUs {
  <#
  .SYNOPSIS
    Create nested OUs for testing
  #>
  $import_mockOUs = Import-Csv -Path .\MockOUs.csv
  [string]$DCPath = 'DC={0}' -f ($DomainName.ToUpper() -replace '\.', ',DC=')
  [string]$RootOUPath = ('OU=' + $OUName + ',' + $DCPath)
  Invoke-LabCommand -ScriptBlock {
    $import_mockOUs | ForEach-Object {
      if ($_.RootOU -ne $OUName) {
        if ((Get-ADOrganizationalUnit -Filter *).Name -contains $_.RootOU) {
          [string]$OUPath = ('OU=' + $_.RootOU + ',' + $RootOUPath)
          New-ADOrganizationalUnit -Name $_.OUName -Path $OUPath
        }
        else {
          Write-Warning -Message "OU named $($_.OUName) is not valid due to nesting issue"
        }
      }
      else {
        [string]$OUPath = $RootOUPath
        New-ADOrganizationalUnit -Name $_.OUName -Path $OUPath
      }
    }
  } -ComputerName DC1 -Variable (Get-Variable -Name OUName), (Get-Variable DCPath), (Get-Variable import_mockOUs), (Get-Variable RootOUPath) -PassThru
}

function Add-LabMockUsers {
  # python.exe .\csvgen.py $DomainName
  $import_mockusers = Import-Csv -Path .\UserMockList.csv
  [string]$DCPath = 'DC={0}' -f ($DomainName.ToUpper() -replace '\.', ',DC=')
  [string]$RootOUPath = ('OU=' + $OUName + ',' + $DCPath)
  Invoke-LabCommand -ScriptBlock {
    [int]$idx = 0
    [string]$OUPath = ("OU=Students," + $RootOUPath)
    $import_mockusers | ForEach-Object {
      if (($idx -ge 60) -and ($idx -lt 100)) {
        $OUPath = ("OU=Profs,OU=Employer," + $RootOUPath)
      }
      elseif ($idx -ge 100) {
        $OUPath = ("OU=Administrative,OU=Employer," + $RootOUPath)
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
        -PassThru
      $idx = $idx + 1
    }
  } -Variable (Get-Variable -Name import_mockusers), (Get-Variable -Name OUName), (Get-Variable DCPath), (Get-Variable RootOUPath) -ComputerName DC1 -PassThru
}

function Enable-Activation {
  <#
  .SYNOPSIS
    Uses MAS <https://massgrave.dev/> to activate all the MS Software
   #>
  param (
    [Parameter(Mandatory)]
    [array]$ServerMachines,
    [Parameter(Mandatory)]
    [array]$ClientMachines
  )
  Copy-LabFileItem -Path .\Microsoft-Activation-Scripts\MAS\All-In-One-Version -DestinationFolderPath C: -ComputerName (Get-LabVM)
  # Needed for Windows Server (non-GUI)
  Copy-LabFileItem -Path .\ClipUp.exe -DestinationFolderPath C:\All-In-One-Version -ComputerName (Get-LabVM)
  # Server Editions doesn't support HWID Activation
  Invoke-LabCommand -ScriptBlock {
    cmd.exe /C "C:\All-In-One-Version\MAS_AIO.cmd /KMS38"
  } -ComputerName $ServerMachines -PassThru
  if ($Office) {
    Invoke-LabCommand -ScriptBlock {
      cmd.exe /C "C:\All-In-One-Version\MAS_AIO.cmd /HWID /KMS-Office /KMS-RenewalTask"
    } -ComputerName $ClientMachines -PassThru
  }
  else {
    Invoke-LabCommand -ScriptBlock {
      cmd.exe /C "C:\All-In-One-Version\MAS_AIO.cmd /HWID"
    } -ComputerName $ClientMachines -PassThru
  }
}

function Add-MockData {
  Add-LabDefaultOU
  Add-LabDefaultAdministrator
  Add-LabMockOUs
  Add-LabMockUsers
}

New-Lab
$ServerMachines, $ClientMachines = Add-LabVMs
Install-Lab -ErrorAction Stop -DelayBetweenComputers 15
Enable-Activation -ServerMachines $ServerMachines -ClientMachines $ClientMachines
if ($MockData) {
  Add-MockData
}
