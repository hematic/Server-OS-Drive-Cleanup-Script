**Server-OS-Drive-Cleanup-Script**

Script Information

Created Date - 12/5/2016

Last Updated - 12/14/2016

Version - 3.0

Created By - Phillip Marshall

**Script Pre-requisites**

1) Powershell should be run as admin when this script is executed.

**Script Process**

1.	Prompts the user for the computer name to run the script against (or you can just enter nothing for local host).
2.	Tests PS Remoting against that server to verify the user has access.
3.	Gathers the current free space on the C drive.
4.	Cleans all temp paths.
5. Gathers all user profiles.
6. Cleans each user profile's temp and downloads folder.
7.	Tests for and cleans old Symantec virus definitions. (The old folders still stay they do not appear to be removeable.)
8.	Runs CleanMGR
9.	Runs DISM
10. Removes any IIS logs older than 30 days for any website.
11. Removes unnecessary windows update files.
12. Cleans all items older than x days from the recycle bin. (Default of 7)
