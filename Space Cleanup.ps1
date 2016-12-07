#Script version 2.0
#last Edit Date 12/07/2016

function Get-recyclebin{
    [CmdletBinding()]
    Param
    (
        $RetentionTime = "7",
        [Switch]$DeleteItems
    )

    $RecycledFiles = @()
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
            $Size = $Recycler.GetDetailsOf($item,3)
            $SizeArray = $Size -split " "
            $Decimal = $SizeArray[0] -replace ",","."

            If ($SizeArray[1] -contains "bytes") { $Size = [int]$Decimal /1024 }
            If ($SizeArray[1] -contains "KB")    { $Size = [int]$Decimal }
            If ($SizeArray[1] -contains "MB")    { $Size = [int]$Decimal * 1024 }
            If ($SizeArray[1] -contains "GB")    { $Size = [int]$Decimal *1024 *1024 }

            $Object = New-Object Psobject -Property @{
                Computer = $env:COMPUTERNAME
                DateRun  = $(Get-Date)
                Name     = $Item.Name
                Type     = $Item.Type
                SizeKb   = $size
                Path     = $Item.path
                "Deleted Date" = $DeletedDatetime
                "Deleted Days" = $DeletedDays }

            $RecycledFiles += $Object

            If ($DeleteItems){
                Remove-Item -Path $item.Path -Confirm:$false -Force -Recurse
            }
        }
    }

    switch ($DeleteItems)
    {
        $True {
                
        }
        $False {
            If(($RecycledFiles | measure-object).count -gt 0){
                Write-output $RecycledFiles
            }
            Else{
                Write-Output $Null
            }
        }
    }                   
}

Function Clean-Path{

    Param
    (
        [String]$Path
    )

    If(Test-Path $Path){
        Write-output "Cleaning $Path"
        Foreach($Item in $(Get-ChildItem -Path $Path -Recurse)){
    
            Try{
                Remove-item -Path $item.FullName -Confirm:$False -Recurse -ErrorAction Stop
            }
            Catch [System.Exception]{
                Write-verbose "$($Item.path) - $($_.Exception.Message)"
            }
        }
        Write-host "Cleaned!" -ForegroundColor Green
    }

}

Function Get-FreeSpace{
    $RawFreespace = (Get-WmiObject Win32_logicaldisk | Where-Object {$_.DeviceID -eq 'C:'}).freespace
    $FreeSpaceGB = [decimal]("{0:N2}" -f($RawFreespace/1gb))
    Write-output $FreespaceGB
}

Function Get-IISLogPaths{
    
    $LogInfo = @()

    Try{
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

##########################
#Calculate Starting Value#
##########################
$OrigFreeSpace = Get-FreeSpace
Write-host "Current Free Space on the 'C' Drive : $OrigFreeSpace GB" -ForegroundColor Yellow

################################################
#Delete Files and Folders from Temp Directories#
################################################
$VerbosePreference = 'SilentlyContinue'

Clean-path -Path 'C:\windows\Temp'
Clean-path -Path 'C:\Temp'
Clean-path -Path 'C:\ProgramData\Microsoft\Windows\WER\ReportArchive'
Clean-path -Path 'C:\ProgramData\Microsoft\Windows\WER\ReportQueue'
Clean-path -Path 'C:\Users\Default\AppData\Local\Temp'
Clean-path -Path 'C:\ServiceProfiles\LocalService\AppData\Local\Temp'

################################################
#Delete Old Symantec Virus Definitions#
################################################
Try{
    $VirusDefsPath = Get-ItemProperty "HKLM:\SOFTWARE\Symantec\Symantec Endpoint Protection\CurrentVersion\content" -ErrorAction Stop | select -ExpandProperty VirusDefs
    $Folders = Get-ChildItem -Path $VirusDefsPath -Directory | Where-object {$_.Name -match "([0-9]{8}[.][0-9]{3})"} | Sort-object -Property lastwritetime -Descending
    [Int]$i = 1
    Foreach($Folder in $Folders){
        If($i -gt 1){
            Clean-Path -Path $Folder.fullname    
        }
        $i++
    }
}
Catch [System.Exception]{
    Write-Host "Symantec Definition Directory could not be located. Skipping removal of old definitions." -ForegroundColor Red
}

##########################
#Run Windows Disk Cleanup#
##########################
Write-Output "Running Windows Disk Cleanup With Parameters"
$ErrorActionPreference = 'Stop'
Try{
    Start-Process -FilePath Cleanmgr -ArgumentList '/sagerun:1' -Wait
    Write-Host "Cleaned!" -ForegroundColor Green
}
Catch [System.Exception]{
  Write-host "cleanmgr is not installed! To use this portion of the script you must install the following windows features:" -ForegroundColor Red
  Write-host "Desktop-Experience, Ink-Handwriting" -ForegroundColor Red

}
$ErrorActionPreference = 'SilentlyContinue'

Write-Host "Cleaned!" -ForegroundColor Green

###########################################
#Running DISM to cleanup ServicePack Files#
###########################################
Write-Output "Running DISM to clean old servicepack files"
$DISMResult = dism.exe /online /cleanup-Image /spsuperseded

If($DISMResult -match 'The operation completed successfully'){
    Write-Host "Cleaned!" -ForegroundColor Green
}
Else{
    Write-Host "Unable to clean old ServicePack Files." -ForegroundColor Red
}

#############################
#Delete Windows Update Files#
#############################
Write-verbose "Temporarily disabling the Windows update service."
Try{
    Get-Service -Name wuauserv | Stop-Service -Force -ErrorAction Stop
    $WUpdateError = $false
}
Catch [System.Exception]{
    Write-host "Unable to stop the Windows update service. Skipping this part of the script." -ForegroundColor Red
    $WUpdateError = $true
}

If($WUpdateError -eq $False){
    Write-verbose "Deleting files from 'C:\Windows\SoftwareDistribution\'"
    Get-ChildItem "C:\Windows\SoftwareDistribution\*" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -force -recurse -ErrorAction SilentlyContinue     
}

Write-verbose "Reenabling the Windows update service."
Get-Service -Name wuauserv | Start-Service

#####################
#Delete Old IIS Logs#
#####################
Try{
    $VerbosePreference = 'SilentlyContinue'
    Import-Module WebAdministration -ErrorAction Stop
    $VerbosePreference = 'Continue'
    $IISInstalled = $True
}
Catch [System.Exception]{
    Write-host "Unable to load the Web Administration server module. This server probably doesn't have IIS." -ForegroundColor Yellow
    $IISInstalled = $False
}
Finally{
    $VerbosePreference = 'Continue'
    If($IISInstalled -eq $True){
        $LogPaths = Get-IISLogPaths
        If($LogPaths -eq 'No Websites'){
            Write-Host "No Websites were found on this server so no IIS log files will be present." -ForegroundColor Yellow
        }
        Else{
            Foreach($Item in $LogPaths){
                Write-Verbose "Checking Website : $($item.sitename)"
                $LogFiles = Get-ChildItem $Item.LogPath -Recurse -File *.log | Where LastWriteTime -lt ((get-date).AddDays(30))
                if ($LogFiles.Count -gt 0){ 
                    ForEach ($File in $LogFiles){ 
                        Write-Verbose "$($File.BaseName) is older than 30 days and will be deleted"
                        Get-item $File | Remove-Item -Verbose 
                    } 
                } 
                ELSE{ 
                    Write-Host "No IIS Log Files Older than 30 days for this site." -ForegroundColor Green
                }
            }
            Write-Host "Cleanup of old IIS Log files completed!" -ForegroundColor Green
        }

    }
}

###################
#Empty Recycle Bin#
###################
Write-Output "Emptying the Recycle Bin"
Get-Recyclebin -DeleteItems
Write-Host "Cleaned!" -ForegroundColor Green
Start-Sleep 10

########################
#Calculate Final Values#
########################
$FinalFreeSpace = Get-FreeSpace
$SpaceRecovered = $OrigFreeSpace - $FinalFreeSpace

If($SpaceRecovered -lt 0){
    Write-Host "Less than a gig of Free Space was recovered." -ForegroundColor Yellow
}
ElseIf($SpaceRecovered -eq 0){
    Write-host "No Space Was saved :("
}
Else{
    Write-host "Current Free Space on the 'C' Drive : $FinalFreeSpace GB" -ForegroundColor Yellow
    $SpaceRecovered = $OrigFreeSpace - $FinalFreeSpace
    Write-host "Space Recovered : $SpaceRecovered GB" -ForegroundColor Yellow
}
