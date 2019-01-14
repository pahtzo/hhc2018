<#
    .SYNOPSIS

        KringleCon 2018 - Ransomware Recovery 9.4
        Recovers all WANNACOOKIE? encrypted files in live mode.

        Author: Nick DeBaggis
        License: BSD 3-Clause
        Required Dependencies: Windows 10 64bit, Powershell 5.1
        Optional Dependencies: None

    .DESCRIPTION

        This script recovers all WANNACOOKIE? encrypted files in the current user's profile directory
        and sub-directories.

        Requires the WANNACOOKIE? ransomware to be running on the system.  You have to manually
        find the PID for that process before running this script.

        Does NOT require the pre-extracted Public Key Encrypted Key (p_k_e_k) and AES key hash (k_h) from
        the Powershell process memory dump.  We pull these variables directly from the WANNACOOKIE? Powershell
        process using Enter-PSHostProcess and Debug-Runspace cmdlets.  This is a live recovery!

        After recovery the WANNACOOKIE? powershell process will terminate.

        See https://www.youtube.com/watch?v=wd12XRq2DNk for details on analyzing Powershell malware.

    .PARAMETER wannacookiepid

        Required Process ID of the Powershell process running WANNACOOKIE?

    .EXAMPLE

        PS C:\> Get-Process 'powershell' | Where-Object {$_.Id -ne $pid}

        Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
        -------  ------    -----      -----     ------     --  -- -----------
            953      57   137144     154272      43.03   2032   1 powershell

        PS C:\> .\wannacookie-recovery-live.ps1 -wannacookiepid 2032

        Perform live mode recovery of all WANNACOOKIE? encrypted files where PID 2032
        is the likely WANNACOOKIE? powershell process.

    .LINK
        https://www.youtube.com/watch?v=wd12XRq2DNk
        https://www.holidayhackchallenge.com/2018/story.html
        https://kringlecon.com/

 #>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [Int]$wannacookiepid
)


function H2B {
    param($HX)
    $HX = $HX -split '(..)' | ? { $_ }
    ForEach ($value in $HX){
        [Convert]::ToInt32($value,16)
    }
}

function A2H(){
    Param($a)
    $c = ''
    $b = $a.ToCharArray();
    Foreach ($element in $b) {
        $c = $c + " " + [System.String]::Format("{0:X}", [System.Convert]::ToUInt32($element))
    }
    return $c -replace ' '
}

function H2A() {
    Param($a)
    $outa
    $a -split '(..)' | ? { $_ }  | forEach {[char]([convert]::toint16($_,16))} | forEach {$outa = $outa + $_}
    return $outa
}

function B2H {
    param($DEC)
    $tmp = ''
    ForEach ($value in $DEC){
        $a = "{0:x}" -f [Int]$value
        if ($a.length -eq 1){
            $tmp += '0' + $a
        } else {
            $tmp += $a
        }
    }
    return $tmp
}

function Sha1([String] $String) {
    $SB = New-Object System.Text.StringBuilder
        [System.Security.Cryptography.HashAlgorithm]::Create("SHA1").ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))|%{
        [Void]$SB.Append($_.ToString("x2"))
    }
    $SB.ToString()
}

function Priv_Key_Dec($key_bytes, [byte[]]$pfx) {
    $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2
    $cert.Import($pfx)
    $encKey = $cert.PrivateKey.Decrypt($key_bytes, $true)
    return $encKey
}

function get_over_dns($f) {
    $h = ''
    foreach ($i in 0..([convert]::ToInt32($(Resolve-DnsName -Server erohetfanu.com -Name "$f.erohetfanu.com" -Type TXT).Strings, 10)-1)) {
        $h += $(Resolve-DnsName -Server erohetfanu.com -Name "$i.$f.erohetfanu.com" -Type TXT).Strings
    }
    return (H2A $h)
}

function unearthfoe {
    param($pkek, $sha1check)
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

    Get-Process 'powershell' | Where-Object {$_.Id -ne $pid}

    Start-Job -ScriptBlock {Start-Sleep 10;$wc = New-Object System.Net.WebClient;$wc.DownloadString('http://127.0.0.1:8080/');}
    Enter-PSHostProcess -Id <WANNACOOKIE PID>
    Get-Runspace
    Debug-Runspace -Name Runspace1
    . .\wannacookie-recovery-live.ps1
    $Pub_key_encrypted_Key
    $Key_Hash
    unearthfoe $Pub_key_encrypted_Key $Key_Hash
    detach
    Exit-PSHostProcess

    if(Test-Path $($env:userprofile+'\Desktop\wannacookie.key')){
        $hexkey = Get-Content $($env:userprofile+'\Desktop\wannacookie.key')
        "Stealing back my cookies! AES key: " + $hexkey
        $wc = New-Object System.Net.WebClient
        $wc.DownloadString('http://127.0.0.1:8080/decrypt?key='+$hexkey)
        Remove-Item $($env:userprofile+'\Desktop\wannacookie.key')
    }

#>

    "Checking if Powershell process $pid contains wannacookie compressed xor killswitch variable S1...`r`n" | Tee-Object -FilePath $($env:userprofile+'\Desktop\wannacookie-log.txt') -Append
    if($S1 -eq $null){
        "Powershell process $pid does not contain wannacookie compressed xor killswitch!`r`n" | Tee-Object -FilePath $($env:userprofile+'\Desktop\wannacookie-log.txt') -Append
        return
    }
    "Powershell process $pid contains wannacookie compressed xor killswitch variable S1, starting AES key recovery...`r`n" | Tee-Object -FilePath $($env:userprofile+'\Desktop\wannacookie-log.txt') -Append
    $pfxb64 = "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"
    [byte[]]$pfx = [System.Convert]::FromBase64String($pfxb64)

    $binkey = (Priv_Key_Dec $(H2B $pkek) $pfx)

    $hexkey = $(B2H $binkey)
    $keyhash = $(sha1 $hexkey)

    if($keyhash -eq $sha1check){
        $hexkey | Out-File -Encoding ASCII -NoNewLine $($env:userprofile+'\Desktop\wannacookie.key')
        "`r`nAES key is good, hash matches!`r`naeskey   : $hexkey`r`nsha1     : $keyhash`r`nsha1check: $sha1check`r`ncookie_id: $($c_id[$c_id.Count - 1])" | Tee-Object -FilePath $($env:userprofile+'\Desktop\wannacookie-log.txt') -Append
        "`r`nTemporarily saving AES hexkey to your desktop for decryption: wannacookie.key" | Tee-Object -FilePath $($env:userprofile+'\Desktop\wannacookie-log.txt') -Append
        "`r`nGetting your cookies back using AES key: $hexkey ..." | Tee-Object -FilePath $($env:userprofile+'\Desktop\wannacookie-log.txt') -Append
        return
    }
    else {
        "Failure: AES key hash doesn't match extracted hash." | Tee-Object -FilePath $($env:userprofile+'\Desktop\wannacookie-log.txt') -Append
        return
    }
}

function Wannacookie-DecryptCookies($ppid){
    if ($(netstat -ano | Select-String "127.0.0.1:8080").length -eq 0){
        "Port 8080 is closed, wannacookie powershell isn't running.  You might be paying the ransom.  Exiting." | Tee-Object -FilePath $($env:userprofile+'\Desktop\wannacookie-log.txt')
        return
    }
    Add-Type -AssemblyName System.Windows.Forms
    "WannaCookie Recovery v3.14.1592 - Nick DeBaggis 20190109." | Tee-Object -FilePath $($env:userprofile+'\Desktop\wannacookie-log.txt')
    "`r`nStarting a web request job to force a break in wannacookie." | Tee-Object -FilePath $($env:userprofile+'\Desktop\wannacookie-log.txt') -Append
    Start-Job -ScriptBlock {Start-Sleep 5;$wc = New-Object System.Net.WebClient;$wc.DownloadString('http://127.0.0.1:8080/');}
    "`r`nEntering wannacookie powershell process $ppid" | Tee-Object -FilePath $($env:userprofile+'\Desktop\wannacookie-log.txt') -Append
    Enter-PSHostProcess -Id $ppid
    [System.Windows.Forms.SendKeys]::SendWait("Debug-Runspace -Name Runspace1{ENTER}");
    [System.Windows.Forms.SendKeys]::SendWait(". $PSScriptRoot\wannacookie-recovery-live.ps1{ENTER}");
    [System.Windows.Forms.SendKeys]::SendWait("unearthfoe `$p_k_e_k `$k_h{ENTER}");
    [System.Windows.Forms.SendKeys]::SendWait("detach{ENTER}");
    [System.Windows.Forms.SendKeys]::SendWait("Exit-PSHostProcess{ENTER}");

    Start-Job -ScriptBlock {
        Start-Sleep 10;
        if($hexkey = Get-Content $($env:userprofile+'\Desktop\wannacookie.key')){
            $wc = New-Object System.Net.WebClient
            $($wc.DownloadString('http://127.0.0.1:8080/decrypt?key='+$hexkey)) | Out-File -FilePath $($env:userprofile+'\Desktop\wannacookie-log.txt') -Append
            "`r`nYou can safely close any WANNACOOKIE? windows." | Out-File -FilePath $($env:userprofile+'\Desktop\wannacookie-log.txt') -Append
            Remove-Item $($env:userprofile+'\Desktop\wannacookie.key')
            Start-Process $($env:userprofile+'\Desktop\wannacookie-log.txt')
        }
        else {
            "`r`nPub_key_encrypted_key not found in powershell process $ppid" | Tee-Object -FilePath $($env:userprofile+'\Desktop\wannacookie-log.txt') -Append
            "`r`nIf the debugger window is still attached you should hit 'CTRL-C' in the session to exit." | Tee-Object -FilePath $($env:userprofile+'\Desktop\wannacookie-log.txt') -Append
            Start-Process $($env:userprofile+'\Desktop\wannacookie-log.txt')
        }
    }
}

<#
If we're NOT in the debugger and we have a PID then we were called from the shell.
This avoids infinitely loading ourselves from Debug-Runspace and not finishing the job.
#>
if(-not $PSDebugContext){
    if($wannacookiepid){
        Wannacookie-DecryptCookies -ppid $wannacookiepid
    }
    else{
        Write-Host "Please supply the wannacookie PID: $PSCommandPath -wannacookiepid <PID>" -Foregroundcolor 'Yellow'
    }
}


