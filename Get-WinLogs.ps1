# . .\Loop-RemoteLogs.
# export-clixml for 500 security logs takes about 10 mins...; consider removing and retrieving Security logs separately

param (
    [Parameter(Mandatory=$true)][string]$HostsFile,
    [Parameter(Mandatory=$false)][Switch]$Loop
)

# Read config file containing list of hosts and credentials
$HostFileData = Get-Content $HostsFile

# For each host in the file, retrieve Sysmon logs
do {
    foreach ($line in $HostFileData) {
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
        $WinLogArray = @("System", "Security", "Application")
        $WinEventParameters = @{'Oldest' = $True}
        $WinEventParameters['ComputerName'] = $Computer
        $WinEventParameters['Credential'] = $Credential

        foreach($log in $WinLogArray) {
            Write-Host -----$log-----
            $StartTime = $(get-date)
            $Events = $null

            # FilterHashtable Arguments
            $WinEventFilters = @{ 'LogName' = $log }

            $LogFilename = $Computer + "_" + $log + "_PS.xml"

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

            Write-Host Pulled $Events.count events

            Export-Clixml -InputObject $Events $LogFilename

            $ElapsedTime = $(get-date) - $StartTime
            $TotalTime = "{0:HH:mm:ss}" -f ([datetime]$elapsedTime.Ticks)
            Write-Host Log Retrieval Time: $TotalTime
        }
    }
} while($Loop)