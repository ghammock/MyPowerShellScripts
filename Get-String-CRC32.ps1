<#
The MIT License (MIT)

Copyright (c) 2017 Gary Hammock

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
#>

function Get-String-CRC32
{
    <#
        .SYNOPSIS
            Generates the typical CRC32 value for a given string of text.

        .DESCRIPTION
            Generates the typical CRC32 value for a given string of text.
            An input value of $null or an empty string will be skipped
            instead of generating an error.

        .PARAMETER InputString
            The string whose CRC32 is to be calculated.

        .NOTES
            Name: Get-String-CRC32
            Author: Gary Hammock
            Created: 2017-11-08

        .INPUTS
            System.String.  An array of System.String may be piped
            into this function.

        .OUTPUTS
            System.String


        .EXAMPLE
            Get-String-CRC32 "The quick brown fox jumps over the lazy dog"

            Input                                       CRC32   
            -----                                       -----   
            The quick brown fox jumps over the lazy dog 414fa339



            Description
            -----------
            Generates the CRC32 value of the string "The quick brown fox
            jumps over the lazy dog".

        .EXAMPLE
            Get-String-CRC32 ("test", "simple", "blah")

            Input  CRC32   
            -----  -----   
            test   d87f7e0c
            simple c17b3d02
            blah   ce29615c



            Description
            -----------
            Generates the CRC32 values of each string in the array:
            ("test", "simple", "blah").

        .EXAMPLE
            "test", "simple", "blah" | Get-String-CRC32

            Input  CRC32   
            -----  -----   
            test   d87f7e0c
            simple c17b3d02
            blah   ce29615c



            Description
            -----------
            Generates the CRC32 values of each string in the piped array:
            ("test", "simple", "blah").

        .EXAMPLE
            "test", "simple", "blah" | Get-String-CRC32 | Format-List


            Input : test
            CRC32 : d87f7e0c
            
            Input : simple
            CRC32 : c17b3d02
            
            Input : blah
            CRC32 : ce29615c


            Description
            -----------
            Generates the CRC32 values of each string in the piped array:
            ("test", "simple", "blah") and displays them in list format.
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeLine=$true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string[]]$InputString
    )

    begin
    {
        # We could calculate the CRC table each time, but it's
        # easier and quicker just to store the 256 entries.
        $CRCTable = @(
            #    0          1           2           3
            #---------------------------------------------
            0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, # 000-003 0x00-0x03
            0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3, # 004-007 0x04-0x07
            0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, # 008-011 0x08-0x0b
            0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, # 012-015 0x0c-0x0f
            0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, # 016-019 0x10-0x13
            0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7, # 020-023 0x14-0x17
            0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, # 024-027 0x18-0x1b
            0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5, # 028-031 0x1c-0x1f
            0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, # 032-035 0x20-0x23
            0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, # 036-039 0x24-0x27
            0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, # 040-043 0x28-0x2b
            0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59, # 044-047 0x2c-0x2f
            0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, # 048-051 0x30-0x33
            0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f, # 052-055 0x34-0x37
            0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, # 056-059 0x38-0x3b
            0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, # 060-063 0x3c-0x3f
            0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, # 064-067 0x40-0x43
            0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433, # 068-071 0x44-0x47
            0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, # 072-075 0x48-0x4b
            0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01, # 076-079 0x4c-0x4f
            0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, # 080-083 0x50-0x53
            0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, # 084-087 0x54-0x57
            0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, # 088-091 0x58-0x5b
            0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65, # 092-095 0x5c-0x5f
            0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, # 096-099 0x60-0x63
            0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb, # 100-103 0x64-0x67
            0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, # 104-107 0x68-0x6b
            0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, # 108-111 0x6c-0x6f
            0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, # 112-115 0x70-0x73
            0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f, # 116-119 0x74-0x77
            0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, # 120-123 0x78-0x7b
            0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad, # 124-127 0x7c-0x7f
            0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, # 128-131 0x80-0x83
            0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, # 132-135 0x84-0x87
            0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, # 136-139 0x88-0x8b
            0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1, # 140-143 0x8c-0x8f
            0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, # 144-147 0x90-0x93
            0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7, # 148-151 0x94-0x97
            0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, # 152-155 0x98-0x9b
            0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, # 156-159 0x9c-0x9f
            0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, # 160-163 0xa0-0xa3
            0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b, # 164-167 0xa4-0xa7
            0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, # 168-171 0xa8-0xab
            0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79, # 172-175 0xac-0xaf
            0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, # 176-179 0xb0-0xb3
            0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, # 180-183 0xb4-0xb7
            0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, # 184-187 0xb8-0xbb
            0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d, # 188-191 0xbc-0xbf
            0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, # 192-195 0xc0-0xc3
            0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713, # 196-199 0xc4-0xc7
            0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, # 200-203 0xc8-0xcb
            0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, # 204-207 0xcc-0xcf
            0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, # 208-211 0xd0-0xd3
            0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777, # 212-215 0xd4-0xd7
            0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, # 216-219 0xd8-0xdb
            0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45, # 220-223 0xdc-0xdf
            0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, # 224-227 0xe0-0xe3
            0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, # 228-231 0xe4-0xe7
            0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, # 232-235 0xe8-0xeb
            0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9, # 236-239 0xec-0xef
            0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, # 240-243 0xf0-0xf3
            0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf, # 244-247 0xf4-0xf7
            0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, # 248-251 0xf8-0xfb
            0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d  # 252-255 0xfc-0xff

        )  # End of CRC32Table

    }  # End of begin block.

    process
    {
        if ($InputString -eq $null)
        {
            Write-Host "Received null as input.  Skipping `$null.`n"
            return
        }

        foreach ($item in $InputString)
        {
            if (($item -ne $null) -and ($item -ne [string]::Empty))
            {
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($item)
                $crc32 = 0xffffffff
                
                $object = New-Object PSObject -Property @{
                    Input = $item
                }
                
                foreach ($b in $bytes)
                {
                  $index = ($crc32 -bxor $b) -band 0xff
                  $part1 = $CRCTable[$index]
                  if ($crc32 -ge 0)
                  {
                      $part2 = ($crc32 -shr 8)
                  }
                  else
                  {
                      $part2 = ($crc32 -shr 8) + (0x02 -shl (-bnot 8))
                  }
                
                  $crc32 =$part1 -bxor $part2
                }
                
                $crc32 = -bnot $crc32
                [string]$hexoutput = -join ($crc32 | `
                                     foreach { "{0:x2}" -f $_ })
                
                $object = Add-Member -InputObject $object `
                                     -MemberType NoteProperty `
                                     -Name "CRC32" `
                                     -Value $hexoutput `
                                     -PassThru

                Write-Output $object
            }
            else
            {
                Write-Host "Received empty string or `$null" `
                         + "as input.  Skipping.`n"
            }

        }  # End of foreach ($item in $InputString).
    }  # End of process block.
}