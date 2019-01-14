<#
    .SYNOPSIS

        KringleCon 2018 - Ransomware Recovery 9.4
        Recovers WANNACOOKIE? encrypted files in offline mode.

        Author: Nick DeBaggis
        License: BSD 3-Clause
        Required Dependencies: Windows 10 64bit, Powershell 5.1
        Optional Dependencies: None

    .DESCRIPTION

        This script recovers all WANNACOOKIE? encrypted files in the current user's profile.

        Requires the pre-extracted Public Key Encrypted Key (p_k_e_k) and AES key hash (k_h) from
        a Powershell WANNACOOKIE? memory dump.  Does not require the WANNACOOKIE? ransomware
        running on the system.

        p_k_e_k is a hex string 512 in length (512 / 2 * 8 == 2048 bits, public key block size).
        k_h is a hex string 40 in length (40 / 2 * 8 == 160 bits, SHA-1 hash).

        See https://www.youtube.com/watch?v=wd12XRq2DNk and https://github.com/chrisjd20/power_dump
        for details on analyzing Powershell malware.

    .PARAMETER PubKeyEncKeyFile

        Required Public Key Encrypted Key file from power_dump extract (encrypted AES key).

    .PARAMETER AESHashFile

        Required AES key SHA-1 Hash file from power_dump extract (encrypted AES key hash).

    .PARAMETER FileToDecrypt

        Optional decrypt a single WANNACOOKIE? encrypted file.

    .EXAMPLE

        PS C:\> .\wannacookie-recovery-offline.ps1 -PubKeyEncKeyFile .\pkek.txt -AESHashFile .\kh.txt -FileToDecrypt .\alabaster_passwords.elfdb.wannacookie

        Decrypt a single WANNACOOKIE? encrypted file.
        
    .EXAMPLE

        PS C:\> .\wannacookie-recovery-offline.ps1 -PubKeyEncKeyFile .\pkek.txt -AESHashFile .\kh.txt

        Decrypt all WANNACOOKIE? encrypted files in the current user's profile directory and sub-directories.

    .LINK
        https://www.youtube.com/watch?v=wd12XRq2DNk
        https://github.com/chrisjd20/power_dump
        https://www.holidayhackchallenge.com/2018/story.html
        https://kringlecon.com/

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [String[]]$PubKeyEncKeyFile,

    [Parameter(Mandatory=$true)]
    [String[]]$AESHashFile,

    [Parameter(Mandatory=$false)]
    [String[]]$FileToDecrypt
)

$functions = {
    function decrypt_file() {
        param($key, $File)
        [byte[]]$key = $key
        $Suffix = "`.wannacookie"
        [System.Reflection.Assembly]::LoadWithPartialName('System.Security.Cryptography')
        [System.Int32]$KeySize = $key.Length * 8
        $AESP = New-Object 'System.Security.Cryptography.AesManaged'
        $AESP.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $AESP.BlockSize = 128
        $AESP.KeySize = $KeySize
        $AESP.Key = $key
        $FileSR = New-Object System.IO.FileStream($File, [System.IO.FileMode]::Open)
        $DestFile = ($File -replace $Suffix)
    
        $FileSW = New-Object System.IO.FileStream($DestFile, [System.IO.FileMode]::Create)
        [Byte[]]$LenIV = New-Object Byte[] 4
        $FileSR.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null
        #$FileSR.Read($LenIV, 0, 3) | Out-Null
        $FileSR.Read($LenIV, 0, 4) | Out-Null
        [Int]$LIV = [System.BitConverter]::ToInt32($LenIV, 0)
        [Byte[]]$IV = New-Object Byte[] $LIV
        $FileSR.Seek(4, [System.IO.SeekOrigin]::Begin) | Out-Null
        $FileSR.Read($IV, 0, $LIV) | Out-Null
        $AESP.IV = $IV
        $Transform = $AESP.CreateDecryptor()
    
        $CryptoS = New-Object System.Security.Cryptography.CryptoStream($FileSW, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write)
        [Int]$Count = 0
        [Int]$BlockSzBts = $AESP.BlockSize / 8
        [Byte[]]$Data = New-Object Byte[] $BlockSzBts
        Do {
            $Count = $FileSR.Read($Data, 0, $BlockSzBts)
            $CryptoS.Write($Data, 0, $Count)
        }
        While($Count -gt 0)
        $CryptoS.FlushFinalBlock()
        $CryptoS.Close()
        $FileSR.Close()
        $FileSW.Close()
        Clear-variable -Name "key"
        #Remove-Item $File
    }
}

function H2B {
    param($HX)
    $HX = $HX -split '(..)' |  ? {
        $_
    }
    ForEach($value in $HX) {
        [Convert]::ToInt32($value, 16)
    }
}

function A2H() {
    Param($a)
    $c = ''
    $b = $a.ToCharArray() 
    Foreach($element in $b) {
        $c = $c + " " + [System.String]::Format("{0:X}", [System.Convert]::ToUInt32($element))
    }
    return $c -replace ' '
}

function H2A() {
    Param($a)
    $outa
    $a -split '(..)' |  ? {$_} | forEach {
        [char]([convert]::toint16($_, 16))
    } | forEach {
        $outa = $outa + $_
    }
    return $outa
}

function B2H {
    param($DEC)
    $tmp = ''
    ForEach($value in $DEC) {
        $a = "{0:x}" -f[Int]$value
        if ($a.length -eq 1) {
            $tmp += '0' + $a
        } else {
            $tmp += $a
        }
    }
    return $tmp
}

function sha1([String]$String) {
    $SB = New-Object System.Text.StringBuilder
    [System.Security.Cryptography.HashAlgorithm]::Create("SHA1").ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String)) |  % {
        [Void]$SB.Append($_.ToString("x2"))
    }
    $SB.ToString()
}

function decrypt_aes_key($key_bytes, [byte[]]$pfx) {
    $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2
    $cert.Import($pfx)
    $encKey = $cert.PrivateKey.Decrypt($key_bytes, $true)
    return $encKey
}

function decrypt_all_files {
    param($key, $allfiles)
    $tcount = 12
    for ($file = 0; $file -lt $allfiles.length; $file++) {
        while ($true) {
            $running = @(Get-Job | Where-Object {
                    $_.State -eq 'Running'
                })
            if ($running.Count -le $tcount) {
                Start-Job -ScriptBlock {
                    param($key, $File)
                    try {
                        decrypt_file $key $File
                    } catch {
                        $_.Exception.Message | Out-String | Out-File $($env:userprofile+'\Desktop\ps_log.txt') -append
                    }
                } -args $key, $allfiles[$file] -InitializationScript $functions
                break
            } else {
                Start-Sleep -m 200
                continue
            }
        }
    }
}

<#
    erohetfanu - unearthfoe?

    "-----BEGIN CERTIFICATE-----" | Out-File .\server.crt
    $(get_over_dns("7365727665722E637274")) | Out-File .\server.crt -append
    "-----END CERTIFICATE-----" | Out-File .\server.crt -append

    $(get_over_dns("7365727665722E6B6579")) | Out-File .\server.key

    Is there a way to do this in powershell/.net without using openssl?
    openssl pkcs12 -export -in server.crt -inkey server.key -out server.pfx

    $pfxb64 = [System.Convert]::ToBase64String($(Get-Content -Encoding Byte .\server.pfx))

    Static pkek and sha1 from memory dump FTW!
    pkek = "3cf903522e1a3966805b50e7f7dd51dc7969c73cfb1663a75a56ebf4aa4a1849d1949005437dc44b8464dca05680d531b7a971672d87b24b7a6d672d1d811e6c34f42b2f8d7f2b43aab698b537d2df2f401c2a09fbe24c5833d2c5861139c4b4d3147abb55e671d0cac709d1cfe86860b6417bf019789950d0bf8d83218a56e69309a2bb17dcede7abfffd065ee0491b379be44029ca4321e60407d44e6e381691dae5e551cb2354727ac257d977722188a946c75a295e714b668109d75c00100b94861678ea16f8b79b756e45776d29268af1720bc49995217d814ffd1e4b6edce9ee57976f9ab398f9a8479cf911d7d47681a77152563906a2c29c6d12f971"
    sha1check = "b0e59a5e0f00968856f22cff2d6226697535da5b"
    key: fbcfc121915d99cc20a3d3d5d84f8308 sha1: b0e59a5e0f00968856f22cff2d6226697535da5bn 
#>

"`r`nWannaCookie Recovery (Offline) v3.14.1592 - Nick DeBaggis 20190109." | Tee-Object -FilePath $($env:userprofile+'\Desktop\wannacookie-log.txt')

if ($(netstat -ano | Select-String "127.0.0.1:8080").length -ne 0){
    "Port 8080 is open, wannacookie powershell might be running.  Try the live recovery script first.  Exiting." | Tee-Object -FilePath $($env:userprofile+'\Desktop\wannacookie-log.txt') -Append
    return
}

if(-not (Test-Path -Path $PubKeyEncKeyFile)){
    "Public key encrypted key file doesn't exist"
    return
}
if(-not (Test-Path -Path $AESHashFile)){
    "AES key hash file doesn't exist"
    return
}

$PubKeyEncKey = Get-Content -Encoding String $PubKeyEncKeyFile
$AESHash = Get-Content -Encoding String $AESHashFile

$pfxb64 = "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"
[byte[]]$pfx = [System.Convert]::FromBase64String($pfxb64)

$binkey = (decrypt_aes_key $(H2B $PubKeyEncKey) $pfx)
$hexkey = $(B2H $binkey)
$keyhash = $(sha1 $hexkey)

if($keyhash -eq $AESHash){
    $akey = $(H2B $hexkey)
    "`r`nAES key is good, hash matches!`r`naeskey   : $hexkey`r`nsha1     : $keyhash`r`nsha1check: $AESHash" | Tee-Object -FilePath $($env:userprofile+'\Desktop\wannacookie-log.txt') -Append
    "`r`nGetting your cookies back using AES key: $hexkey ..." | Tee-Object -FilePath $($env:userprofile+'\Desktop\wannacookie-log.txt') -Append

    [array]$allcookies = $(Get-ChildItem -Path $($env:userprofile) -Recurse -Filter *.wannacookie | where { ! $_.PSIsContainer } | Foreach-Object {$_.Fullname})

    if($FileToDecrypt -and (Test-Path -Path $FileToDecrypt)){
        $allcookies = $(Get-ChildItem -Path $FileToDecrypt -Filter *.wannacookie | where { ! $_.PSIsContainer } | Foreach-Object {$_.Fullname})
    }

    decrypt_all_files $akey $allcookies
    Get-Job | Wait-Job

    "`r`nWannacookie offline recovery complete." | Tee-Object -FilePath $($env:userprofile+'\Desktop\wannacookie-log.txt') -Append
    Start-Process $($env:userprofile+'\Desktop\wannacookie-log.txt')    
}


