function Convert-Base64 {
    <#
        .SYNOPSIS
            Encodes and Decodes an input file to and from Base64

        .DESCRIPTION
            Encodes and Decodes an input file to and from Base64

        .NOTES
            Name: Convert-Base64
            Author: Gary Hammock
            Created: 2017-10-30

        .PARAMETER InputFile
            The name of the file to be encoded/decoded to or from Base64.

        .PARAMETER OutputFile
            The name of the file that will receive the encoded/decoded content.

        .PARAMETER FromBase64
            A flag to set for decoding FROM Base64.

        .OUTPUTS
            IO.File

        .EXAMPLE
            Convert-Base64 image.png b64.txt

            Description
            -----------
            Encodes the file 'image.png' to Base64 and stores the content
            in 'b64.txt'

        .EXAMPLE
            Convert-Base64 b64.txt image.png -FromBase64

            Description
            -----------
            Decodes the Base64 content in file 'b64.txt' and outputs the
            decoded bytes in 'image.png'

        .LINK
            IETF RFC-4648:
            https://tools.ietf.org/html/rfc4648

            C99 Compliant Base64 Code Listing:
            http://josefsson.org/base-encoding/

            For our GNU/Linux counterparts:
            http://www.gnu.org/software/coreutils/manual/coreutils.html#base64-invocation
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true)]
        [string]$InputFile,

        [Parameter(Position=1, Mandatory=$true)]
        [string]$OutputFile,

        [Parameter()]
        [switch]$FromBase64=$false
    )

    switch($FromBase64)
    {
        $true {
            $Base64 = Get-Content $InputFile -Raw
            [IO.File]::WriteAllBytes($OutputFile, [Convert]::FromBase64String($Base64))
        }

        $false {
            $Base64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($InputFile))
            [IO.File]::WriteAllText($OutputFile, $Base64)
        }
    }
}