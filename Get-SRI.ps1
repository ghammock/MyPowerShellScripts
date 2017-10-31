function Get-SRI {
    <#
        .SYNOPSIS
            Generates the integrity attribute for a given file based on SubResource
            Integrity (SRI) requirements.

        .DESCRIPTION
            Uses the .Net assemblies to generate a SHA hash of a given resource and
            generates the base-64 representation of that hash as an SRI-compliant tag.

        .PARAMETER Filename
            The file that will be used as a linked subresource whose integrity value
            is to be calculated.

        .PARAMETER Hash
            The type of SHA hash in the set of (SHA256, SHA384, and SHA512).
            SHA384 is the default.

        .NOTES
            Name: Get-SRI
            Author: Gary Hammock
            Created: 2017-10-31

        .INPUTS
            None.  You cannot pipe objects into Get-SRI.

        .OUTPUTS
            System.String

        .LINK
            SubResource Integrity
            https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity

        .EXAMPLE
            Get-SRI filename.css
            integrity="sha384-wvfXpqpZZVQGK6TAh5PVlGOfQNHSoD2xbE+QkPxCAFlNEevoEH3Sl0sibVcOQVnN"

            Description
            -----------
            Generates the integrity attribute of "filename.css" using the SHA384 (default) algorithm.

        .EXAMPLE
            Get-SRI filename.css SHA512
            integrity="sha512-SfTiTlX6kk+qitfevl/7LibUOeJWlt9rbyDn92a1DqWOw9vWG2MFoays0sgObmWazO5BQPiFucnnEAjpAB+/Sw=="

            Description
            -----------
            Generates the integrity attribute of "filename.css" using the SHA512 algorithm.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true)]
        [string]$Filename, 
    
        [Parameter(Position=1)]
        [ValidateSet('SHA256', 'SHA384', 'SHA512')]
        [string]$Hash='SHA384'
    )

    switch ($Hash) {
        "SHA256" { $SHA = [System.Security.Cryptography.SHA256]::Create() }
        "SHA384" { $SHA = [System.Security.Cryptography.SHA384]::Create() }
        "SHA512" { $SHA = [System.Security.Cryptography.SHA512]::Create() }
        default {
            Write-Host "Unsupported SHA hashing algorithm."
            return
        }
    }

    Write-Verbose "File: $Filename"
    Write-Verbose "Hash Algorithm: $Hash"

    $IntegrityText = 'integrity="{0}-{1}"'

    $File = Get-Content $Filename -Raw

    try {
        # Cue Weezer, "I got my Hash Bytes."  :P
        $HashBytes = $SHA.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($File))
        $Base64Hash = [System.Convert]::ToBase64String($HashBytes)

        Write-Verbose "Hash value: $([System.BitConverter]::ToString($HashBytes).Replace('-', ''))"
        Write-Verbose "Base64 value: $Base64Hash"
    
        $Hash = $Hash.ToLower()
        $IntegrityAttr = [string]::format($IntegrityText, $Hash, $Base64Hash)
        Write-Host $IntegrityAttr
    }
    finally {
        if ($SHA -ne $null) {
            $SHA.Dispose()
        }
    }
}