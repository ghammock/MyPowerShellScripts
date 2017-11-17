function Get-SRI {
    <#
        .SYNOPSIS
            Generates the integrity attribute for given files based on
            SubResource Integrity (SRI) requirements.

        .DESCRIPTION
            Uses the .Net assemblies to generate a SHA hash of a given
            resource and generates the base-64 representation of that
            hash as an SRI-compliant integrity attribute.

        .PARAMETER Path
            The path to a file or directory whose integrity attribute value
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

            File                Integrity Attribute                                                                
            ----                -------------------                                                                
            C:\...\filename.css integrity="sha384-bsGkvB1NLsaPUZL6GG0N5H9GOW9DK6KiHrrDvO57EJXoD9H3gzlohtuPENw9/24L"


            Description
            -----------
            Generates the integrity attribute of "filename.css" using the
            SHA384 (default) algorithm.

        .EXAMPLE
            Get-SRI filename.css SHA512

            File                Integrity Attribute                                                                                        
            ----                -------------------                                                                                        
            C:\...\filename.css integrity="sha512-NDWv4n2v59EOoj+dDvXfD4uGGTCOXkLAnm+DhQtyYxpZL4lMSymTX5HD8i5NEcF+1YLBkgvByardYsJaA1W6MA=="


            Description
            -----------
            Generates the integrity attribute of "filename.css" using the
            SHA512 algorithm.

        .EXAMPLE
            Get-SRI \path\to\directory\* SHA256

            File                        Integrity Attribute                                            
            ----                        -------------------                                            
            C:\...\awesome.css.file.css integrity="sha256-vloo/0moJBraR3GgG6Di+AzNG2EO0WXmpMqfmhlQKsI="
            C:\...\filename.css         integrity="sha256-QUyqZrt5vIjBumoqQV0jM8CgGqscFfdGhN+nVCqX0vc="
            C:\...\filename.map         integrity="sha256-L9kHpSw7UP2DGOcYfAmVRflHvkhthqCCIt1IOoSJW6k="
            C:\...\filename_1_debug.css integrity="sha256-LpykTdjMm+jVLpDWiYOkH8bYiithb4gajMYnIngj128="
            C:\...\test.css.file.css    integrity="sha256-agLdPBbE868MuEXUBISKalq3ZoJovFP5nJQilYpQJL4="
            C:\...\test.css.file.map    integrity="sha256-OnWOmMndQbWhR065+2rXauW/hVr2psKMCgrws0DJhg8="
            C:\...\zzz.css              integrity="sha256-eZrrJcwDc/3uDhsdt61sL2oOBY362qM3lon1gyExkL0="


            Description
            -----------
            Generates the integrity attribute of all the files in the given
            directory using the SHA256 algorithm.

        .EXAMPLE
            Get-SRI .\Documents\14303_Argus\www\assets\js\bootstrap*, .\Documents\14303_Argus\www\assets\css\bootstrap*

            File                         Integrity Attribute                                                                
            ----                         -------------------                                                                
            C:\...\bootstrap.min.js      integrity="sha384-alpBpkh1PFOepccYVYDB4do5UnbKysX5WZXm3XxPqe5iKTfUKjNkCk9SaVuEZflJ"
            C:\...\bootstrap.min.js.map  integrity="sha384-Wld3F+TH3S/fmDKsVlofUEe0OBuZFYSdlOU4bmD7yZc0bw/FkdD4EFe3WSorjvH6"
            C:\...\bootstrap.min.css     integrity="sha384-PsH8R72JQ3SOdhVi3uxftmaW6Vc51MKb0q5P2rRUpPvrszuE4W1povHYgTpBfshb"
            C:\...\bootstrap.min.css.map integrity="sha384-2kiF5bJ7yk9TINZNNCCw8vE2wPzNeUafRG5WMqh43Pee5LMjaplzwISmvLTVCijr"


            Description
            -----------
            Generates the integrity attribute of all the files in _each_
            directory whose filenames start with "bootstrap".

        .EXAMPLE
            Get-ChildItem .\path\to\assets\js\jquery* | Get-SRI -Hash SHA256 | Format-List
            
            File                : C:\...\jquery.min.js
            Integrity Attribute : integrity="sha256-hwg4gsxgFZhOsEEamdOYGBf13FyQuiTwlAQgxVSNgt4="
            
            File                : C:\...\jquery.min.map
            Integrity Attribute : integrity="sha256-sCRVDlkzQ9EPnHpxIfl23YYZp2jC1mP6KdaJUt6alL0="


            Description
            -----------
            Generates the integrity attribute of all the files whose name
            starts with "jquery" in the given directory, piped into the
            function from the command line, using the SHA256 algorithm,
            and displayed in list format.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeLine=$true)]
        [Alias("PSPath", "FullName")]
        [string[]]$Path, 
    
        [Parameter(Position=1)]
        [ValidateSet('SHA256', 'SHA384', 'SHA512')]
        [string]$Hash='SHA384'
    )

    begin
    {
        switch ($Hash) {
            "SHA256" { $sha = [System.Security.Cryptography.SHA256]::Create() }
            "SHA384" { $sha = [System.Security.Cryptography.SHA384]::Create() }
            "SHA512" { $sha = [System.Security.Cryptography.SHA512]::Create() }
            default {
                Write-Host "Unsupported SHA hashing algorithm."
                return
            }
        }

        if (($Path -ne $null) -and ($Path.Count -gt 0))
        {
            $Path = Resolve-Path $Path
        }
    }

    process
    {
        if ($Path -eq $null)
        {
            Write-Host "Received null as input.  Skipping `$null.`n"
            return
        }

        $integrityText = 'integrity="{0}-{1}"'
        $Hash = $Hash.ToLower()  # SRI requires that the hash algorithm be lowercase.

        foreach ($item in $Path)
        {
            if (![string]::IsNullOrEmpty($item))
            {
                $file = (Resolve-Path $item).ProviderPath
                if (Test-Path $file -PathType Container)
                {
                    Write-Warning ([string]::Format("{0} is a directory and cannot be hashed", $file))
                    continue
                }

                Write-Verbose "File: $file"
                Write-Verbose "Hash Algorithm: $Hash"

                $displayPath = (Split-Path -Path $file -Qualifier) `
                              + [IO.path]::DirectorySeparatorChar `
                              + "..." + [IO.path]::DirectorySeparatorChar `
                              + (Split-Path -Path $file -Leaf)

                $object = New-Object PSObject -Property @{
                        File = $displayPath
                }

                # Cue Weezer, "I got my Hash Bytes."  :P
                $hashBytes = $sha.ComputeHash([IO.File]::ReadAllBytes($file))
                $base64Hash = [System.Convert]::ToBase64String($hashBytes)

                Write-Verbose "Hash value: $([System.BitConverter]::ToString($hashBytes).Replace('-', ''))"
                Write-Verbose "Base64 value: $base64Hash"

                $integrityAttr = [string]::format($integrityText, $Hash, $base64Hash)

                $object = Add-Member -InputObject $object `
                                 -MemberType NoteProperty `
                                 -Name "Integrity Attribute" `
                                 -Value $integrityAttr `
                                 -PassThru

                Write-Output $object

            }  # End of if (!null).
        }  # End of foreach().
    }  # End of process block.

    end
    {
        if ($sha -ne $null) {
            $sha.Dispose()
        }
    }
}