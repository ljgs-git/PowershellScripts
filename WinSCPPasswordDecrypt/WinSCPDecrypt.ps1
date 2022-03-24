<#
.SYNOPSIS
    Decode credentials stored by WinSCP, when no MasterPassword is used.
.DESCRIPTION
    WinSCP stores credentials eihter in WinSCP.ini or in the registry. By default these Passwords are only encoded and can easily be dedoded with this script.
.EXAMPLE
    PS C:\> WinSCPDecrypt.ps1 -iniPath C:\WinSCP.ini
    Decodes credentials stored in the file C:\WinSCP.ini
.INPUTS
    iniPath. Path to the WinSCP.ini file that should be decoded.
.OUTPUTS
    Output (if any)
.NOTES
    Partially stolen from https://github.com/YuriMB/WinSCP-Password-Recovery and https://devblogs.microsoft.com/scripting/use-powershell-to-work-with-any-ini-file/
#>

[CmdletBinding()]
param (
    #Path to WinSCP.ini 
    [Parameter(Mandatory)]
    [string]
    $iniPath
)

$PW_MAGIC = 0xA3
$PW_FLAG = 0xFF

function decode {
    param (
        # Name of the host the encrypted password is for.
        [Parameter(Mandatory)]
        [string]
        $hostname,
        # Name of the user the encrypted password is for.
        [Parameter(Mandatory)]
        [string]
        $username,
        # Encoded Password of winscp
        [Parameter(Mandatory)]
        [string]
        $passwd
    )
    
    $key = $username + $hostname

    $passBytes = [byte[]]($passwd -split '(..)' -ne '' | foreach{[byte]"0x$_"})

    Write-Debug "passBytes $(($passBytes | ForEach-Object ToString X2) -join ' ')"
    
    $flag, $passBytes = decode-next-char $passBytes

    $hex = ($passBytes | ForEach-Object ToString X2) -join " "
    Write-Debug "flag ($flag), passBytes ($hex)"
    if ($flag -eq $PW_FLAG) {
        $ignore, $passBytes = decode-next-char $passBytes
        $length, $passBytes = decode-next-char $passBytes
        
        Write-Debug "length ($length), passBytes $(($passBytes | ForEach-Object ToString X2) -join ' ')"
    } else {
        $length = $flag
    }

    $toBeDeleted, $passBytes = decode-next-char $passBytes
    $passBytes = $passBytes[$toBeDeleted..$passBytes.Count]

    Write-Debug "toBeDeleted ($toBeDeleted), passBytes $(($passBytes | ForEach-Object ToString X2) -join ' ')"

    $clearpasswd = ""

    for ($i = 0; $i -lt $length;$i++) {
        $val, $passBytes = decode-next-char $passBytes
        $clearpasswd += [char] $val
    }

    if ($flag -eq $PW_FLAG) {
        if ( -not $clearpasswd.StartsWith($key)) {
            throw "Decoding failed key ($key) not in clearpass ($clearpasswd)"
            return
        }
        return $clearpasswd[$key.Length..$clearpasswd.Length]

    }
    return $clearpasswd
}


function decode-next-char {
    param (
        # encodedByteString
        [Parameter(Mandatory)]
        [byte[]]
        $encBS
    )
    if ($encBs.Count -le 0) {
        return 0,$encBS
    }
    $a = $encBS[0]
    $encBS = $encBS[1..$encBS.Count]
    
    return  ( ($a -bxor $PW_MAGIC) -bxor 0xff),$encBS

}


function Get-IniContent {
    param (
        # Parameter help description
        [Parameter(Mandatory)]
        [string]
        $iniPath
    )
    $ini = @{}
    switch -regex -file $iniPath
    {
        "^\[(.+)\]" # Section
        {
            $section = $matches[1]
            $ini[$section] = @{}
            $CommentCount = 0
        }
        "^(;.*)$" # Comment
        {
            $value = $matches[1]
            $CommentCount = $CommentCount + 1
            $name = “Comment” + $CommentCount
            $ini[$section][$name] = $value
        }
        "(.+?)\s*=(.*)" # Key
        {
            $name,$value = $matches[1..2]
            $ini[$section][$name] = $value
        }
    }
    return $ini
}


function Get-IniCredentials {
    param (
        # Parameter help description
        [Parameter(Mandatory)]
        [string]
        $iniPath
    )

    $ini = Get-IniContent -iniPath $iniPath

    $creds = @{}

    $sessions = $ini.keys | ForEach-Object {if ($_ -like "Sessions*") {$ini[$_]}}
    
    foreach ($session in $Sessions) {
        if ("password" -in $session.keys) {
            $creds["$($session.username)@$($session.hostname)"] = @{
                username = $session.username
                hostname = $session.hostname
                passwd = $session.password
                tunneled = $false
            }
            if ("Tunnel" -in $session.keys) {
                $creds["$($session.username)@$($session.hostname)"].tunneled = 1 -eq $session.Tunnel
            }
        }
        if ("TunnelPassword" -in $session.keys) {
            $creds["$($session.TunnelUsername)@$($session.TunnelHostname)"] = @{
                username = $session.TunnelUsername
                hostname = $session.TunnelHostname
                passwd = $session.TunnelPassword
                tunneled = $false
            }
        }
    }

    return $creds
}

$creds = Get-IniCredentials  -iniPath $iniPath
foreach ($key in $creds.keys) {
    $cred = $creds[$key]

    $passwd = decode -hostname $cred.hostname -username $cred.username -passwd $cred.passwd
    $res = @{
        target = $key
        password = $passwd -join ""
        tunneled = $cred.Tunneled
    }
    Write-Output ([PSCustomObject] $res)
} 


