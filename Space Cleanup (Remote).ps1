#Script version 2.0
#last Edit Date 12/07/2016

Function Get-Recyclebin{
    [CmdletBinding()]
    Param
    (
        $ComputerOBJ,
        $RetentionTime = "7"
    )

    If($ComputerOBJ.PSRemoting -eq $true){
        $Result = Invoke-Command -ComputerName $ComputerOBJ.ComputerName -ScriptBlock {
        
        Try{
            $Shell = New-Object -ComObject Shell.Application
            $Recycler = $Shell.NameSpace(0xa)
            $Recycler.Items() 

            foreach($item in $Recycler.Items())
            {
                $DeletedDate = $Recycler.GetDetailsOf($item,2) -replace "\u200f|\u200e","" #Invisible Unicode Characters
                $DeletedDatetime = Get-Date $DeletedDate 
                [Int]$DeletedDays = (New-TimeSpan -Start $DeletedDatetime -End $(Get-Date)).Days

                If($DeletedDays -ge $RetentionTime)
                {
                    Remove-Item -Path $item.Path -Confirm:$false -Force -Recurse
                }
            }
        }
        Catch [System.Exception]{
            $RecyclerError = $true
        }
        Finally{
            If($RecyclerError -eq $False){
                Write-output $True 
            }
            Else{
                Write-Output $False
            }
        }

        
    } -Credential $ComputerOBJ.Credential
        If($Result -eq $True){
            Write-Host "All recycler items older than $RetentionTime days were deleted" -ForegroundColor Green
        }
        Else{
            Write-Host "Unable to deleted some items in the Recycle Bin." -ForegroundColor Red
        }
    }
    Else{
        Try{
            $Shell = New-Object -ComObject Shell.Application
            $Recycler = $Shell.NameSpace(0xa)
            $Recycler.Items() 

            foreach($item in $Recycler.Items())
            {
                $DeletedDate = $Recycler.GetDetailsOf($item,2) -replace "\u200f|\u200e","" #Invisible Unicode Characters
                $DeletedDatetime = Get-Date $DeletedDate 
                [Int]$DeletedDays = (New-TimeSpan -Start $DeletedDatetime -End $(Get-Date)).Days

                If($DeletedDays -ge $RetentionTime)
                {
                    Remove-Item -Path $item.Path -Confirm:$false -Force -Recurse
                }
            }
        }
        Catch [System.Exception]{
            $RecyclerError = $true
        }
        Finally{
            If($RecyclerError -eq $true){
                Write-Host "Unable to deleted some items in the Recycle Bin." -ForegroundColor Red
            }
            Else{
                Write-Host "All recycler items older than $RetentionTime days were deleted" -ForegroundColor Green
            }
        }
    }    
}

Function Clean-Path{

    Param
    (
        [String]$Path,
        $ComputerOBJ
    )
    Write-Host "`t...Cleaning $Path"
    If($ComputerOBJ.PSRemoting -eq $True){

        Invoke-Command -ComputerName $ComputerOBJ.ComputerName -ScriptBlock {

            If(Test-Path $Using:Path){

                Foreach($Item in $(Get-ChildItem -Path $Using:Path -Recurse)){
    
                    Try{
                        Remove-item -Path $item.FullName -Confirm:$False -Recurse -ErrorAction Stop
                    }
                    Catch [System.Exception]{
                        Write-verbose "$($Item.path) - $($_.Exception.Message)"
                    }
                }
            }

        } -Credential $ComputerOBJ.Credential
    }
    Else{

        If(Test-Path $Path){
        
        Foreach($Item in $(Get-ChildItem -Path $Path -Recurse)){
    
            Try{
                Remove-item -Path $item.FullName -Confirm:$False -Recurse -ErrorAction Stop
            }
            Catch [System.Exception]{
                Write-verbose "$($Item.path) - $($_.Exception.Message)"
            }
        }
    }



    }
}

Function Get-OrigFreeSpace{

    Param
    (
        $ComputerOBJ
    )

    Try{
        $RawFreespace = (Get-WmiObject Win32_logicaldisk -ComputerName $ComputerOBJ.ComputerName -Credential $ComputerOBJ.Credential -ErrorAction Stop | Where-Object {$_.DeviceID -eq 'C:'}).freespace
        $FreeSpaceGB = [decimal]("{0:N2}" -f($RawFreespace/1gb))
        Write-host "Current Free Space on the OS Drive : $FreeSpaceGB GB" -ForegroundColor Yellow
    }
    Catch [System.Exception]{
        $FreeSpaceGB = $False
        Write-Host "Unable to pull free space from OS drive. Press enter to Exit..." -ForegroundColor Red    
    }
    Finally{
        $ComputerOBJ | Add-Member -MemberType NoteProperty -Name OrigFreeSpace -Value $FreeSpaceGB
        Write-output $ComputerOBJ
    }
}

Function Get-FinalFreeSpace{

    Param
    (
        $ComputerOBJ
    )

    Try{
        $RawFreespace = (Get-WmiObject Win32_logicaldisk -ComputerName $ComputerOBJ.ComputerName -Credential $ComputerOBJ.Credential -ErrorAction Stop | Where-Object {$_.DeviceID -eq 'C:'}).freespace
        $FreeSpaceGB = [decimal]("{0:N2}" -f($RawFreespace/1gb))
        Write-host "Final Free Space on the OS Drive : $FreeSpaceGB GB" -ForegroundColor Yellow
    }

    Catch [System.Exception]{
        $FreeSpaceGB = $False
        Write-Host "Unable to pull free space from OS drive. Press enter to Exit..." -ForegroundColor Red    
    }
    Finally{
        $ComputerOBJ | Add-Member -MemberType NoteProperty -Name FinalFreeSpace -Value $FreeSpaceGB
        Write-output $ComputerOBJ
    }
}

Function Get-IISLogPaths{

    Param
    (
        $ComputerOBJ
    )    

    If($ComputerOBJ.PSRemoting -eq $true){
        $Results = Invoke-command -ComputerName $ComputerOBJ.ComputerName -ScriptBlock {
            Try{
                Import-Module WebAdministration -ErrorAction Stop
                $Websites = Get-WebSite -ErrorAction Stop
                Write-output $Websites
            }
            Catch [System.Exception]{
                Write-Output "No Websites"
            }
        } -Credential $ComputerOBJ.credential
        If($Results -eq "No Websites"){
            Write-output "No Websites"
        }
        Else{
            $LogInfo = @()
            ForEach($WebSite in $Websites){
                $Path = "$($Website.logFile.directory)\w3scv$($website.id)".replace("%SystemDrive%",$env:SystemDrive)
                $obj = New-Object psobject @{
                    LogPath = $Path
                    SiteName = $WebSite.name
                }
                $LogInfo += $Obj
            }
            Write-output $LogInfo
        }
    }
    Else{
        Try{
            Import-Module WebAdministration -ErrorAction Stop
            $Websites = Get-WebSite -ErrorAction Stop
        }
        Catch [System.Exception]{
            Write-output "No Websites"
        }

        ForEach($WebSite in $Websites){
            $Path = "$($Website.logFile.directory)\w3scv$($website.id)".replace("%SystemDrive%",$env:SystemDrive)
            $obj = New-Object psobject @{
                LogPath = $Path
                SiteName = $WebSite.name
            }
            $LogInfo += $Obj
        }

        Write-output $LogInfo
    }
}  

Function Get-Computername {

    Write-Host "Please enter the computername to connect to or just hit enter for localhost" -ForegroundColor Yellow
    $ComputerName = Read-Host

    if($ComputerName -eq '' -or $ComputerName -eq $null){
        $obj = New-object PSObject -Property @{
            ComputerName = $env:COMPUTERNAME
            Remote = $False
        }
    }
    else{
        $obj = New-object PSObject -Property @{
            ComputerName = $Computername
            Remote = $True
        }
    }

    Write-output $obj

}

Function Test-PSRemoting{

    Param
    (
        $ComputerOBJ
    )

    Write-Host "Please enter your credentials for the remote machine." -ForegroundColor Yellow
    $ComputerOBJ | Add-Member NoteProperty -Name Credential -Value (Get-Credential)

    $RemoteHostname = Invoke-command -ComputerName $ComputerOBJ.Computername -ScriptBlock {hostname} -Credential $ComputerOBJ.Credential -erroraction 'silentlycontinue'

    If($RemoteHostname -eq $ComputerOBJ.Computername){
        Write-Host "PowerShell Remoting was successful" -ForegroundColor Green
        $ComputerOBJ | Add-Member NoteProperty -Name PSRemoting -Value $True
    }
    Else {
        Write-host "PowerShell Remoting FAILED press enter to exit script." -ForegroundColor Red
        $ComputerOBJ | Add-Member NoteProperty -Name PSRemoting -Value $False
    }

    Write-output $ComputerOBJ
}

Function TestFor-SymantecPath{

    Param
    (
        $ComputerOBJ
    )
    Write-Host "Attempting to clean old Virus Definitions" -ForegroundColor Yellow
    If($ComputerOBJ.PSRemoting -eq $true){
        
        $Paths = Invoke-command -ComputerName $ComputerOBJ.ComputerName -ScriptBlock {
                    $VirusDefsPath = Get-ItemProperty "HKLM:\SOFTWARE\Symantec\Symantec Endpoint Protection\CurrentVersion\content" -ErrorAction Stop | select -ExpandProperty VirusDefs
                    Try{
                        $Folders = Get-ChildItem -Path $VirusDefsPath -Directory | Where-object {$_.Name -match "([0-9]{8}[.][0-9]{3})"} | Sort-object -Property lastwritetime -Descending
                    }
                    Catch [System.Exception]{
                        $Folders = $null    
                    }
                    Write-Output $Folders
                } -Credential $ComputerOBJ.Credential
        $PathCount = ($Paths | Measure-Object).count
        
        If($PathCount -eq 0){
            Write-Host "Symantec Definition Directory could not be located. Skipping removal of old definitions." -ForegroundColor Red
        }
        ElseIf($PathCount -eq 1){
            Write-Host "Symantec Definition Directory contained only current definitions." -ForegroundColor Green
        }
        Else{
            Write-Host "Symantec Definition Directory contained $PathCount folders." -ForegroundColor Yellow
            Invoke-Command -ComputerName $ComputerOBJ.ComputerName -ScriptBlock {
            
                [Int]$i = 1
                Foreach($Folder in $Using:Paths){
                    If($i -gt 1){
                        Clean-Path -Path $Folder.fullname -ComputerOBJ $Using:ComputerOBJ
                    }
                    $i++
                }
            
            } -Credential $ComputerOBJ.Credential
            Write-host "All Old Virus Definition Files cleaned successfully." -ForegroundColor Green
        }
    }
 
    Else{
        $VirusDefsPath = Get-ItemProperty "HKLM:\SOFTWARE\Symantec\Symantec Endpoint Protection\CurrentVersion\content" -ErrorAction Stop | select -ExpandProperty VirusDefs
        $Paths = Get-ChildItem -Path $VirusDefsPath -Directory | Where-object {$_.Name -match "([0-9]{8}[.][0-9]{3})"} | Sort-object -Property lastwritetime -Descending
        $PathCount = ($Paths | Measure-Object).count
        If($PathCount -eq 0){
            Write-Host "Symantec Definition Directory could not be located. Skipping removal of old definitions." -ForegroundColor Red
        }
        ElseIf($PathCount -eq 1){
            Write-Host "Symantec Definition Directory contained only current definitions." -ForegroundColor Green
        }
        Else{
            Write-Host "Symantec Definition Directory contained $PathCount folders." -ForegroundColor Yellow
            [Int]$i = 1
            Foreach($Folder in $Paths){
                If($i -gt 1){
                    Clean-Path -Path $Folder.fullname -ComputerOBJ $ComputerOBJ  
                }
                $i++
            }
            Write-host "All Old Virus Definition Files cleaned successfully." -ForegroundColor Green
        }
    }
}

Function Run-CleanMGR{

    Param
    (
        $ComputerOBJ
    )

    If($ComputerOBJ.PSRemoting -eq $true){
        Write-Host "Attempting to Run Windows Disk Cleanup With Parameters" -ForegroundColor Yellow
        $CleanMGR = Invoke-command -ComputerName $ComputerOBJ.ComputerName -ScriptBlock {
                        $ErrorActionPreference = 'Stop'
                        Try{
                            Start-Process -FilePath Cleanmgr -ArgumentList '/sagerun:1' -Wait
                            $ErrorActionPreference = 'SilentlyContinue'
                            Write-Output $true
                        }
                        Catch [System.Exception]{
                            $ErrorActionPreference = 'SilentlyContinue'
                            Write-output $False
                        }
                    } -Credential $ComputerOBJ.Credential

        If($CleanMGR -eq $True){
            Write-Host "Windows Disk Cleanup has been run successfully." -ForegroundColor Green
        }
        Else{
            Write-host "Cleanmgr is not installed! To use this portion of the script you must install the following windows features:" -ForegroundColor Red
            Write-host "Desktop-Experience, Ink-Handwriting" -ForegroundColor Red
        }
    }
    Else{

        Write-Host "Attempting to Run Windows Disk Cleanup With Parameters" -ForegroundColor Yellow
        $ErrorActionPreference = 'Stop'
        Try{
            Start-Process -FilePath Cleanmgr -ArgumentList '/sagerun:1' -Wait
            Write-Host "Windows Disk Cleanup has been run successfully." -ForegroundColor Green
        }
        Catch [System.Exception]{
          Write-host "cleanmgr is not installed! To use this portion of the script you must install the following windows features:" -ForegroundColor Red
          Write-host "Desktop-Experience, Ink-Handwriting" -ForegroundColor Red

        }
        $ErrorActionPreference = 'SilentlyContinue'
    }
}

Function Run-DISM{

    Param
    (
        $ComputerOBJ
    )

    If($ComputerOBJ.PSRemoting -eq $true){
    Write-Host "Running DISM to clean old servicepack files" -ForegroundColor Yellow
    $DISM = Invoke-command -ComputerName $ComputerOBJ.ComputerName -ScriptBlock {
                $ErrorActionPreference = 'Stop'
                Try{
                    $DISMResult = dism.exe /online /cleanup-Image /spsuperseded
                    $ErrorActionPreference = 'SilentlyContinue'
                    Write-Output $DISMResult
                }
                Catch [System.Exception]{
                    $ErrorActionPreference = 'SilentlyContinue'
                    Write-output $False
                }
                } -Credential $ComputerOBJ.Credential

    If($DISM -match 'The operation completed successfully'){
        Write-Host "DISM Completed Successfully." -ForegroundColor Green
    }
    Else{
        Write-Host "Unable to clean old ServicePack Files." -ForegroundColor Red
    }
}
    Else{
        Write-Host "Running DISM to clean old servicepack files" -ForegroundColor Yellow
        $ErrorActionPreference = 'Stop'
        Try{
            $DISMResult = dism.exe /online /cleanup-Image /spsuperseded
            $ErrorActionPreference = 'SilentlyContinue'
        }
        Catch [System.Exception]{
            $ErrorActionPreference = 'SilentlyContinue'
            $DISMResult = $False
        }
        $ErrorActionPreference = 'SilentlyContinue'
        If($DISMResult -match 'The operation completed successfully'){
            Write-Host "DISM Completed Successfully." -ForegroundColor Green
        }
        Else{
            Write-Host "Unable to clean old ServicePack Files." -ForegroundColor Red
        }
    }
}

Function Process-IISLogs{

    Param
    (
        $ComputerOBJ
    )

    Write-Host "Attempting to load the Web Administration Server Module" -ForegroundColor Yellow
    If($ComputerOBJ.PSRemoting -eq $true){
        $ModuleLoad = Invoke-command -ComputerName $ComputerOBJ.ComputerName -ScriptBlock {
            Try{
                Import-Module WebAdministration -ErrorAction Stop
                Write-Output $True
            }
            Catch [System.Exception]{
                Write-Output = $False
            }
        } -Credential $ComputerOBJ.Credential

        If($ModuleLoad -eq $True){
            Write-Host "Web Administration Module loaded successfully. This server probably has IIS." -ForegroundColor Green
            $LogPaths = Get-IISLogPaths -ComputerOBJ $ComputerOBJ
            If($LogPaths -eq 'No Websites'){
                Write-Host "No Websites were found on this server so no IIS log files will be present." -ForegroundColor Yellow
            }
            Else{
                Foreach($Item in $LogPaths){
                    Write-Verbose "Checking Website : $($Item.sitename)"
                    $LogFiles = Invoke-Command -ComputerName $ComputerOBJ.ComputerName -ScriptBlock {
                        Try{
                            $LogFiles = Get-ChildItem $Item.LogPath -Recurse -File *.log -ErrorAction Stop | Where LastWriteTime -lt ((get-date).AddDays(30))
                        }
                        Catch [System.Exception]{
                            $LogFiles = $Null
                        }
                        Write-output $LogFiles
                    } -Credential $ComputerOBJ.Credential
                
                    If ($($LogFiles | Measure-Object).count -gt 0){ 
                        ForEach ($File in $LogFiles){ 
                            Delete-IISLogFile -ComputerOBJ $Computerobj -LogFile $File
                        } 
                    } 
                    ELSE{ 
                        Write-Host "No IIS Log Files Older than 30 days for this site." -ForegroundColor Green
                    }
                }
                Write-Host "Cleanup of old IIS Log files completed!" -ForegroundColor Green
            }
        }
        Else{
            Write-host "Unable to load the Web Administration server module. This server probably doesn't have IIS." -ForegroundColor Yellow
        }
    }
    Else{
        Try{
            Import-Module WebAdministration -ErrorAction Stop
            $ModuleLoad = $True
        }
        Catch [System.Exception]{
            $ModuleLoad = $False
        }
        If($ModuleLoad -eq $True){
            Write-Host "Web Administration Module loaded successfully. This server probably has IIS." -ForegroundColor Green
            $LogPaths = Get-IISLogPaths
            If($LogPaths -eq 'No Websites'){
                Write-Host "No Websites were found on this server so no IIS log files will be present." -ForegroundColor Yellow
            }
            Else{
                Foreach($Item in $LogPaths){
                    Write-Host "Checking Website : $($item.sitename)" -ForegroundColor Yellow
                    Try{
                        $LogFiles = Get-ChildItem $Item.LogPath -Recurse -File *.log -ErrorAction Stop | Where LastWriteTime -lt ((get-date).AddDays(30))
                    }
                    Catch [System.Exception]{
                        Write-Host "No Log File directory for this site." -ForegroundColor Red
                    }
                    If ($($LogFiles | Measure-Object).count -gt 0){ 
                        ForEach ($File in $LogFiles){ 
                            Delete-IISLogFile -ComputerOBJ $Computerobj -LogFile $File
                        } 
                    } 
                    Else{ 
                        Write-Host "No IIS Log Files Older than 30 days for this site." -ForegroundColor Green
                    }
                }
                Write-Host "Cleanup of old IIS Log files completed!" -ForegroundColor Green
            }
        }
        Else{
            Write-host "Unable to load the Web Administration server module. This server probably doesn't have IIS." -ForegroundColor Yellow
        }

    }
}

Function Delete-IISLogFile{

    Param
    (
        $ComputerOBJ,
        $LogFile
    )
    If($ComputerOBJ.PSRemoting -eq $true){
    
        Invoke-command -ComputerName $ComputerOBJ.ComputerName -ScriptBlock {
            Get-item $USING:LogFile | Remove-Item
        } -Credential $ComputerOBJ.Credential
    }
    Else{
        Get-item $:LogFile | Remove-Item
    }
    Write-Host "`t$($File.BaseName) was older than 30 days and has been deleted"
}

Function Set-WindowsUpdateService{

    param
    (
        $ComputerOBJ
    )
    Write-Host "Deleting files from 'C:\Windows\SoftwareDistribution\'" -ForegroundColor Yellow
    
    If($ComputerOBJ.PSRemoting -eq $true){
        $Result = Invoke-Command -ComputerName $ComputerOBJ.ComputerName -ScriptBlock {
        
            Try{
                Get-Service -Name wuauserv | Stop-Service -Force -ErrorAction Stop
                $WUpdateError = $false
            }
            Catch [System.Exception]{
                $WUpdateError = $true
            }
            Finally{
                If($WUpdateError -eq $False){
                    Get-ChildItem "C:\Windows\SoftwareDistribution\*" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -force -recurse -ErrorAction SilentlyContinue    
                    Get-Service -Name wuauserv | Start-Service
                    Write-output $True 
                }
                Else{
                    Get-Service -Name wuauserv | Start-Service
                    Write-Output $False
                }
            }

        
        } -Credential $ComputerOBJ.Credential
        If($Result -eq $True){
            Write-Host "Files Deleted Successfully" -ForegroundColor Green
        }
        Else{
            Write-Host "Unable to stop the windows update service. No files were deleted." -ForegroundColor Red
        }
    }
    Else{
        Try{
            Get-Service -Name wuauserv | Stop-Service -Force -ErrorAction Stop
            $WUpdateError = $false
        }
        Catch [System.Exception]{
            $WUpdateError = $true
        }
        Finally{
            If($WUpdateError -eq $False){
                Get-ChildItem "C:\Windows\SoftwareDistribution\*" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -force -recurse -ErrorAction SilentlyContinue    
                Get-Service -Name wuauserv | Start-Service
                Write-Host "Files Deleted Successfully" -ForegroundColor Green
            }
            Else{
                Get-Service -Name wuauserv | Start-Service
                Write-Host "Unable to stop the windows update service. No files were deleted." -ForegroundColor Red
            }
        }
    }

}

Clear-Host
$ComputerOBJ = Get-Computername

If($ComputerOBJ.Remote -eq $true){
    $ComputerOBJ = Test-PSRemoting -ComputerOBJ $ComputerOBJ
    If($ComputerOBJ.PSRemoting -eq $False){
        Read-Host
        exit;
    }
}

$ComputerOBJ = Get-OrigFreeSpace -ComputerOBJ $ComputerOBJ

If($ComputerOBJ.OrigFreeSpace -eq $False){
    Read-host
    exit;
}

Clean-path -Path 'C:\windows\Temp' -ComputerOBJ $ComputerOBJ
Clean-path -Path 'C:\Temp' -ComputerOBJ $ComputerOBJ
Clean-path -Path 'C:\ProgramData\Microsoft\Windows\WER\ReportArchive' -ComputerOBJ $ComputerOBJ
Clean-path -Path 'C:\ProgramData\Microsoft\Windows\WER\ReportQueue' -ComputerOBJ $ComputerOBJ
Clean-path -Path 'C:\Users\Default\AppData\Local\Temp' -ComputerOBJ $ComputerOBJ
Clean-path -Path 'C:\ServiceProfiles\LocalService\AppData\Local\Temp' -ComputerOBJ $ComputerOBJ

Write-Host "All Temp Paths have been cleaned" -ForegroundColor Green

TestFor-SymantecPath -ComputerOBJ $ComputerOBJ
Run-CleanMGR -ComputerOBJ $ComputerOBJ
Run-DISM -ComputerOBJ $ComputerOBJ
Process-IISLogs -ComputerOBJ $ComputerOBJ
Set-WindowsUpdateService -ComputerOBJ $ComputerOBJ
Get-Recyclebin -ComputerOBJ $ComputerOBJ

$ComputerOBJ = Get-FinalFreeSpace -ComputerOBJ $ComputerOBJ
$SpaceRecovered = $($Computerobj.finalfreespace) - $($ComputerOBJ.OrigFreeSpace)

If($SpaceRecovered -lt 0){
    Write-Host "Less than a gig of Free Space was recovered." -ForegroundColor Yellow
}
ElseIf($SpaceRecovered -eq 0){
    Write-host "No Space Was saved :("
}
Else{
    Write-host "Space Recovered : $SpaceRecovered GB" -ForegroundColor Yellow
}
