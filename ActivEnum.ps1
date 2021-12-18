function Set-ConsoleColor ($bc, $fc) {
    $Host.UI.RawUI.BackgroundColor = $bc
    $Host.UI.RawUI.ForegroundColor = $fc
    Clear-Host
}
Set-ConsoleColor 'black' 'white' # PowerShell Black Background

# Banner
$banner=@" 
               _   _       ______                       
     /\       | | (_)     |  ____|                      
    /  \   ___| |_ ___   __ |__   _ __  _   _ _ __ ___  
   / /\ \ / __| __| \ \ / /  __| | '_ \| | | | '_ ` _ \ 
  / ____ \ (__| |_| |\ V /| |____| | | | |_| | | | | | |
 /_/    \_\___|\__|_| \_/ |______|_| |_|\__,_|_| |_| |_|
                                                                                                             
                                                                
           By Hamad Abualshook 201701952  
	   Copyrights Bahrain Polytechnic 2021 
                                            
"@
write-host "`n"
write-host "`n"
Write-Host $banner -ForegroundColor Green
$Title = 'Please Select a Language'
# Menu Loop
do {
  [int]$userMenuChoice = 0
  while ( $userMenuChoice -lt 1 -or $userMenuChoice -gt 3) {
    Write-Host "================ $Title ================"
    write-host "`n"
    Write-Host "[1] English"
    Write-Host "[2] Arabic"
    Write-Host "[3] Quit and Exit"
write-host "`n"

    [int]$userMenuChoice = Read-Host "Please choose an option"

    switch ($userMenuChoice) {
      1{
$banner=@"
               _   _       ______                       
     /\       | | (_)     |  ____|                      
    /  \   ___| |_ ___   __ |__   _ __  _   _ _ __ ___  
   / /\ \ / __| __| \ \ / /  __| | '_ \| | | | '_ ` _ \ 
  / ____ \ (__| |_| |\ V /| |____| | | | |_| | | | | | |
 /_/    \_\___|\__|_| \_/ |______|_| |_|\__,_|_| |_| |_|
                                                                                                             
                                                                
           By Hamad Abualshook 201701952  
	       Copyrights Bahrain Polytechnic 2021                                             
"@
Write-Host $banner -ForegroundColor Green
# Menu Loop and User Choice for detailed scans
do {
  [int]$userMenuChoice = 0
  while ( $userMenuChoice -lt 1 -or $userMenuChoice -gt 4) {
    
    $Title = 'Select an Option'
    write-host "`n"
    Write-Host "================ $Title ================"
    write-host "`n"
    Write-Host "1. Perform a Full Scan"
    Write-Host "2. Display Computer Name"
    Write-Host "3. Display IP Address"
    Write-Host "4. Back to main menu"

    [int]$userMenuChoice = Read-Host "Please choose an option"
    write-host "`n"
    switch ($userMenuChoice) {
      1{$banner=@"
               _   _       ______                       
     /\       | | (_)     |  ____|                      
    /  \   ___| |_ ___   __ |__   _ __  _   _ _ __ ___  
   / /\ \ / __| __| \ \ / /  __| | '_ \| | | | '_ ` _ \ 
  / ____ \ (__| |_| |\ V /| |____| | | | |_| | | | | | |
 /_/    \_\___|\__|_| \_/ |______|_| |_|\__,_|_| |_| |_|
                                                                                                             
                                                                
               By Hamad Abualshook 201701952  
	       Copyrights Bahrain Polytechnic 2021                                             
"@
Write-Host $banner -ForegroundColor Green

write-host "`n"
write-host "`n"
write-host "------------------------------------------------------------------"
Start-Transcript -Path "C:\transcripts\transcript.txt" # Log Saving Location
write-host "------------------------------------------------------------------"
write-host "`n"

Write-Host '[*] Scan Started' -ForegroundColor Green # Any header will be colored in Green or Yellow
Get-Date
write-host "`n"

Write-Host '[+] Server Operating System and Architecture' -ForegroundColor Green # OS and Architecture Description 
Get-ComputerInfo -Property "os*" | select OSName, OsArchitecture 

Write-Host '[+] Computer Name' -ForegroundColor Green # Computer Name
$env:COMPUTERNAME
write-host "`n"

Write-Host '[+] IP Address Information' -ForegroundColor Green # IP Address Information
(Get-NetIPAddress | Where-Object {$_.AddressFamily -eq 'IPv4'}).IPAddress 
write-host "`n"

Write-Host '[+] Users on Server Found' -ForegroundColor Green # Users found on server
Get-LocalUser | select Name

Write-Host '[+] Users Full Name' -ForegroundColor Green # Users full name
Get-LocalUser | select FullName  

try # Error Handling
{
    $a = Get-ADDomainController | Select-Object -ExpandProperty Domain
    $b = Get-ADDomainController | Select-Object -ExpandProperty Forest
    write-host '[+] Domain Found:' -ForegroundColor Green # Domain Name
    write-host $a -ForegroundColor White  
    write-host "`n"
    write-host '[+] Forest Found:' -ForegroundColor Green # Forest Name
    write-host $b -ForegroundColor White
    write-host "`n"
}
catch # If error found print the following
{
    Write-Host '[-] Active Directory Not Intalled or Error in Output' -ForegroundColor Yellow 
}
# If funtion with filtering to check users with no pre-auth
if ($a = Get-ADUser -Filter * -Property DoesNotRequirePreAuth | Where-Object {$_.DoesNotRequirePreAuth -eq "True"} | Select-Object -ExpandProperty Name)
{
Write-Host '[+] Found Possible User with no Pre-Auth Enabled:' -ForegroundColor Green # If found print them
write-host $a -ForegroundColor White
write-host "`n"
}
else
{
Write-Host  '[+] Did Not Find Any User with no Pre-Auth Enabled'  -ForegroundColor Yellow # Else print no users found
}

$Shares =  Get-SmbShare | Format-Table | Out-String # Filtering shares
Write-Host  '[+] Found Shares:'  -ForegroundColor Green # Print Shares found
Write-Host  $Shares  -ForegroundColor White
# Print shares in form of table
$ShareAcess =  Get-SmbShare | Get-SmbShareAccess | Where-Object {$_.AccessRight -eq "Full"} | Select-Object -ExpandProperty Name | Format-Table | Out-String 
Write-Host  '[+] Found FULL Right Shares:'  -ForegroundColor Green # Check shares with full rights
Write-Host  $ShareAcess  -ForegroundColor White 

Write-Host  '[+] Found Disabled Users:'  -ForegroundColor Green # Disabled users
Search-ADAccount -AccountDisabled | select name

Write-Host  '[+] Computers on the Domain:'  -ForegroundColor Green # Domain Computers
Get-AdComputer -filter *

Write-Host  '[+] OS and Hostname of the computers in the domain:'  -ForegroundColor Green # OS of Domain Computers
Get-ADDomainController -filter * | select hostname, operatingsystem

Write-Host  '[+] Domain Computers SID:'  -ForegroundColor Green # SID of Domain Computers
Get-AdComputer -filter * | select Name, SID

Write-Host  '[+] AD Users SID:'  -ForegroundColor Green # SID of Domain Users
Get-ADUser -Filter * | Select Name, SID

Write-Host  '[+] Password Policy:'  -ForegroundColor Green # Password Policy
Get-ADDefaultDomainPasswordPolicy

if(Get-Module -ListAvailable | # Check if module installed 
Where-Object { $_.name -eq $name })
{
Write-Host  '[+] Modules Installed:'  -ForegroundColor Green # If installed print installed
Import-Module -Name $name
$true
} 
else
{ 
Write-Host  '[-] Modules Installed:'  -ForegroundColor Green # Else print no modules installed
Write-Host  'No Modules Installed:'  -ForegroundColor Red
} 
write-host "`n"

Write-Host  '[+] Group Policy:'  -ForegroundColor Green # Group policy
get-GPO -all | select DisplayName, gpostatus

write-host "`n"
write-host "------------------------------------------------------------------"
Stop-Transcript
write-host "------------------------------------------------------------------"
write-host "`n"


function take_input() { # Funtion to take user input and keep the loop until terminated 
    param
    (
        [Parameter(Position = 0, ValueFromPipeline = $true)]
        [string]$msg,
        [string]$BackgroundColor = "Black",
        [string]$ForegroundColor = "DarkGreen"
    )

    Write-Host -ForegroundColor $ForegroundColor -NoNewline $msg;
    return Read-Host
}

$choice = take_input 'Press Enter to Quit'}

      2{Write-Host '[+] Computer Name' -ForegroundColor Green 
       $env:COMPUTERNAME
       write-host "`n"}

      3{Write-Host '[+] IP Address Information' -ForegroundColor Green
       (Get-NetIPAddress | Where-Object {$_.AddressFamily -eq 'IPv4'}).IPAddress }

      default {Write-Host "Exited" -ForegroundColor Green 
      write-host "`n"
      

      if ($userMenuChoice -gt 4) {
      write-host 'Invalid Selection' -ForegroundColor Red 
      } 

      }
    }
  }
} while ( $userMenuChoice -ne 4 )
# END OF ENGLISH FUNCTIONS    
  }


      2{$banner=@"
               _   _       ______                       
     /\       | | (_)     |  ____|                      
    /  \   ___| |_ ___   __ |__   _ __  _   _ _ __ ___  
   / /\ \ / __| __| \ \ / /  __| | '_ \| | | | '_ ` _ \ 
  / ____ \ (__| |_| |\ V /| |____| | | | |_| | | | | | |
 /_/    \_\___|\__|_| \_/ |______|_| |_|\__,_|_| |_| |_|
                                                                                                             
                                                                
           By Hamad Abualshook 201701952  
	       Copyrights Bahrain Polytechnic 2021                                             
"@
Write-Host $banner -ForegroundColor Green # Same as English Version, However, Transalated into Arabic as per functional Requirements

do {
  [int]$userMenuChoice = 0
  while ( $userMenuChoice -lt 1 -or $userMenuChoice -gt 4) {
    
    $Title = 'تحديد خيار'
    write-host "`n"
    Write-Host "================ $Title ================"
    write-host "`n"
    Write-Host "1. إجراء مسح كامل"
    Write-Host "2. عرض اسم الكمبيوتر"
    Write-Host "3. عرض عنوان IP"
    Write-Host "4. إنهاء والخروج"

    [int]$userMenuChoice = Read-Host "الرجاء اختيار خيار"
    write-host "`n"
    switch ($userMenuChoice) {
      1{$banner=@"
               _   _       ______                       
     /\       | | (_)     |  ____|                      
    /  \   ___| |_ ___   __ |__   _ __  _   _ _ __ ___  
   / /\ \ / __| __| \ \ / /  __| | '_ \| | | | '_ ` _ \ 
  / ____ \ (__| |_| |\ V /| |____| | | | |_| | | | | | |
 /_/    \_\___|\__|_| \_/ |______|_| |_|\__,_|_| |_| |_|
                                                                                                             
                                                                
               By Hamad Abualshook 201701952  
	       Copyrights Bahrain Polytechnic 2021                                             
"@
Write-Host $banner -ForegroundColor Green

write-host "`n"
write-host "`n"
write-host "------------------------------------------------------------------"
Start-Transcript -Path "C:\transcripts\transcript.txt" 
write-host "------------------------------------------------------------------"
write-host "`n"

Write-Host '[*] بدء المسح' -ForegroundColor Green
Get-Date
write-host "`n"

Write-Host '[+] نظام تشغيل الخادم وهندسته المعمارية' -ForegroundColor Green
Get-ComputerInfo -Property "os*" | select OSName, OsArchitecture 

Write-Host '[+] اسم الكمبيوتر' -ForegroundColor Green 
$env:COMPUTERNAME
write-host "`n"

Write-Host '[+] معلومات عنوان IP' -ForegroundColor Green
(Get-NetIPAddress | Where-Object {$_.AddressFamily -eq 'IPv4'}).IPAddress 
write-host "`n"

Write-Host '[+] تم العثور على المستخدمين على الملقم' -ForegroundColor Green
Get-LocalUser | select Name

Write-Host '[+] اسم المستخدمين الكامل' -ForegroundColor Green
Get-LocalUser | select FullName  

try
{
    $a = Get-ADDomainController | Select-Object -ExpandProperty Domain
    $b = Get-ADDomainController | Select-Object -ExpandProperty Forest
    write-host '[+] تم العثور على المجال:' -ForegroundColor Green
    write-host $a -ForegroundColor White  
    write-host "`n"
    write-host '[+] العثور على الغابات:' -ForegroundColor Green 
    write-host $b -ForegroundColor White
    write-host "`n"
}
catch
{
    Write-Host '[-] Active Directory غير مبلور أو خطأ في الإخراج' -ForegroundColor Yellow
}

if ($a = Get-ADUser -Filter * -Property DoesNotRequirePreAuth | Where-Object {$_.DoesNotRequirePreAuth -eq "True"} | Select-Object -ExpandProperty Name)
{
Write-Host '[+] العثور على مستخدم محتمل بدون تمكين ما قبل Auth:' -ForegroundColor Green
write-host $a -ForegroundColor White
write-host "`n"
}
else
{
Write-Host  '[+] لم يتم العثور على أي مستخدم بدون تمكين ما قبل Auth'  -ForegroundColor Yellow
}

$Shares =  Get-SmbShare | Format-Table | Out-String
Write-Host  '[+] الأسهم التي تم العثور عليها:'  -ForegroundColor Green
Write-Host  $Shares  -ForegroundColor White

$ShareAcess =  Get-SmbShare | Get-SmbShareAccess | Where-Object {$_.AccessRight -eq "Full"} | Select-Object -ExpandProperty Name | Format-Table | Out-String
Write-Host  '[+] العثور على أسهم كاملة اليمين:'  -ForegroundColor Green
Write-Host  $ShareAcess  -ForegroundColor White 

Write-Host  '[+] تم العثور على مستخدمين معطلين:'  -ForegroundColor Green
Search-ADAccount -AccountDisabled | select name

Write-Host  '[+] أجهزة الكمبيوتر على المجال:'  -ForegroundColor Green
Get-AdComputer -filter *

Write-Host  '[+] نظام التشغيل واسم المضيف لأجهزة الكمبيوتر في المجال:'  -ForegroundColor Green
Get-ADDomainController -filter * | select hostname, operatingsystem

Write-Host  '[+] SID أجهزة الكمبيوتر المجال:'  -ForegroundColor Green
Get-AdComputer -filter * | select Name, SID

Write-Host  '[+] معرف أمان لمستخدمي ال AD:'  -ForegroundColor Green
Get-ADUser -Filter * | Select Name, SID

Write-Host  '[+] نهج كلمة المرور:'  -ForegroundColor Green
Get-ADDefaultDomainPasswordPolicy

if(Get-Module -ListAvailable |
Where-Object { $_.name -eq $name })
{
Write-Host  '[+] الوحدات النمطية المثبتة:'  -ForegroundColor Green
Import-Module -Name $name
$true
} 
else
{ 
Write-Host  '[-] الوحدات النمطية المثبتة:'  -ForegroundColor Green
Write-Host  'لا توجد وحدات نمطية مثبتة:'  -ForegroundColor Red
} 
write-host "`n"

Write-Host  '[+] نهج المجموعة:'  -ForegroundColor Green
get-GPO -all | select DisplayName, gpostatus

write-host "`n"
write-host "------------------------------------------------------------------"
Stop-Transcript
write-host "------------------------------------------------------------------"
write-host "`n"


function take_input() {
    param
    (
        [Parameter(Position = 0, ValueFromPipeline = $true)]
        [string]$msg,
        [string]$BackgroundColor = "Black",
        [string]$ForegroundColor = "DarkGreen"
    )

    Write-Host -ForegroundColor $ForegroundColor -NoNewline $msg;
    return Read-Host
}

$choice = take_input 'Press Enter to Quit'}

      2{Write-Host '[+] اسم الكمبيوتر' -ForegroundColor Green 
       $env:COMPUTERNAME
       write-host "`n"}

      3{Write-Host '[+] معلومات عنوان IP' -ForegroundColor Green
       (Get-NetIPAddress | Where-Object {$_.AddressFamily -eq 'IPv4'}).IPAddress }

      default {Write-Host "خرجت" -ForegroundColor Green 
      write-host "`n"
      

      if ($userMenuChoice -gt 4) {
      write-host 'تحديد غير صالح' -ForegroundColor Red 
      } 

      }
    }
  }
} while ( $userMenuChoice -ne 4 )
}



      3{Write-Host "Exited" -ForegroundColor Yellow}



      default {Write-Host "Invalid Selection" -ForegroundColor Red}
    }
  }
} while ( $userMenuChoice -ne 3 )
