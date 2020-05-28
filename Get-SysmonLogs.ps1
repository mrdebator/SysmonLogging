# .\Get-SysmonLogs.ps1 -HostsFile .\hosts.txt -Loop
# Log File Format - [HOST]:[DOMAIN]:[USERNAME]:[PASSWORD]
# By default, the program retrieves the Sysmon logs and saves them as a powershell object in xml format

param (
    [Parameter(Mandatory=$true)][string]$HostsFile,
    [Parameter(Mandatory=$false)][Switch]$SysmonView,
    [Parameter(Mandatory=$false)][Switch]$Loop
)

# Read config file containing list of hosts and credentials
$HostFileData = Get-Content $HostsFile

# For each host in the file, retrieve Sysmon logs
do {
    foreach ($line in $HostFileData) {
        $StartTime = $(get-date)

        $Events = $null
        $SplitEvents = @()

        # Split fields into values
        $line = $line -split (":")
        $Computer = $line[0]
        $Domain = $line[1]
        $Username = $line[2]
        $Password = $line[3]

        Write-Host ----------$Computer----------
    
        # Generate PsCredential object
        $SecureStringPassword = $Password | ConvertTo-SecureString -AsPlainText -Force
        $PSCredentialUsername = $Domain + "\" + $Username
        echo $PSCredentialUsername
        $Credential = New-Object System.Management.Automation.PSCredential($PSCredentialUsername, $SecureStringPassword)
        
        # Get-WinEvent Parameters
        $LogFilename = $Computer + "_Sysmon_PS.xml"
        $WinEventParameters = @{'Oldest' = $True}
        $WinEventParameters['ComputerName'] = $Computer
        $WinEventParameters['Credential'] = $Credential

        # FilterHashtable Arguments
        $WinEventFilters = @{ 'LogName' = 'Microsoft-Windows-Sysmon/Operational' }

        if(Test-Path $LogFilename) {
            $SplitEvents = Import-Clixml -Path $LogFilename
            $DATE = $SplitEvents | select -last 1 | %{$_.TimeCreated} # gets the timestamp of the most recent log in the xml file
            Write-Host Latest Log: $DATE
            $WinEventFilters['StartTime'] = $DATE
        }
        else {
            Write-Host No log history...
        }
        
        # attach FilterHashtable argument
        $WinEventParameters['FilterHashtable'] = $WinEventFilters

        $Events = Get-WinEvent @WinEventParameters -MaxEvents 500
        
        # Thank you Matt...
        $Events | ForEach-Object {
                $Lines = $_.Message –split [System.Environment]::NewLine
                $Id = $_.Id
                $TimeCreated = $_.TimeCreated
                $EventName = $Lines[0] –replace ‘:’
                $Event = New-Object PSObject
                $Event | Add-Member -MemberType ‘NoteProperty’ –Name ‘Id’ –Value $Id
                $Event | Add-Member -MemberType 'NoteProperty' -Name 'TimeCreated' -Value $TimeCreated
                $Event | Add-Member –MemberType ‘NoteProperty’ –Name ‘EventName’ –Value $EventName
                $Lines | Select-Object –Skip 1 | ForEach-Object {
                $PropName,$PropValue = $_ -split ‘: ’
                $PropName = $PropName –replace ‘ ’
                Add-Member –InputObject $Event –MemberType NoteProperty –Name $PropName –Value $PropValue
            }
            $SplitEvents += $Event
        }

        Write-Host Pulled $Events.count events

        Export-Clixml -InputObject $SplitEvents $LogFilename

        $ElapsedTime = $(get-date) - $StartTime
        $TotalTime = "{0:HH:mm:ss}" -f ([datetime]$elapsedTime.Ticks)
        Write-Host Log Retrieval Time: $TotalTime
    
        if($SysmonView) {
            $LogFilename = $Computer + "_SysmonView.xml"
            $WevtutilCmdString = "WEVTUtil query-events 'Microsoft-Windows-Sysmon/Operational' /r:" + $Computer + " /u:" + ($Domain+"\"+$Username) + " /p:" + $Password + " /format:xml /e:sysmonview > " + $LogFilename
            echo $WevtutilCmdString
            Invoke-Expression $WevtutilCmdString
        }
    }

    Start-Sleep (5)  # this is in seconds
} while($Loop)