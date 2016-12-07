# Server-OS-Drive-Cleanup-Script

Script Information

#Created - 12/5/2016
#Last Updated - 12/7/2016
#Version - 2.0
#Created By - Phillip Marshall

Script pre-requisites


1) Powershell should be run as admin when this script is executed.

Script Process

1)	Calculates the amount of freespace on the C drive at the start of the script.
2)	Deletes files and folders from the following temp directories :
    a.	'C:\windows\Temp'
    b.	'C:\Temp'
    c.	'C:\ProgramData\Microsoft\Windows\WER\ReportArchive'
    d.	'C:\ProgramData\Microsoft\Windows\WER\ReportQueue'
    e.	'C:\Users\Default\AppData\Local\Temp'
    f.	'C:\ServiceProfiles\LocalService\AppData\Local\Temp'
3)	Deletes old Symantec antivirus definitions.
    a.	It does leave the folders. I can’t seem to delete those for some reason. ¯\_(ツ)_/¯
4)	Runs the windows disk cleanup utility with parameters.
5)	Runs DISM to cleanup old servicepack files.
6)	Deletes old windows update files.
7)	Deletes IIS logs older than 30 days.
8)	Empty’s the recycle bin.
9)	Outputs the final result of the script with amount of space saved.
