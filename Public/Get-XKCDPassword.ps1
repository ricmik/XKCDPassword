function Get-XKCDPassword {
    <#
    .SYNOPSIS
    This function will create passwords using a dictionary in the same way as https://xkpasswd.net/s/

    .DESCRIPTION
    This function creates a password by selecting random words from a dictionary and adding different characters and digits for spacing and padding.
    The function Get-CryptoRandom is a requirement. 

    .PARAMETER DictionaryPath
    The dictionary with all the words we use to build the password. Use the full path to the file.
    .PARAMETER NumberofWords
    Total number of words selected from the dictionary
    .PARAMETER MinimumWordLength 
    Minimum number of characters per word
    .PARAMETER MaximumWordLength
    Maximum number of characters per word
    .PARAMETER CaseTransformation
    Case transform on the words
    FirstLetterUpperCase, RANDOMupperLOWERCASE, EVERYotherUPPERlowerCASE, lowercase, UPPERCASE
    .PARAMETER SeparatorCharacters
    Symbols to use for spacing between words
    .PARAMETER PaddingDigitsBefore
    Number of digits before the words
    .PARAMETER PaddingDigitsAfter
    Number of digits after the words
    .PARAMETER PaddingSymbols
    Symbols to use for padding
    .PARAMETER PaddingSymbolsBefore
    Number of symbols to add in the front of the password. Symbols are selected from the PaddingSymbols parameter
    .PARAMETER PaddingSymbolsAfter
    Number of symbols to add at the end of the password. Symbols are selected from the PaddingSymbols parameter
    .PARAMETER PaddingToLength
    Instead of using PaddingSymbolsBefore and PaddingSymbolsAfter you can set a specified length to add symbols to the end of the password to create a fixed length password
    .PARAMETER Preset
    Instead of specifying the settings on the command line, you can use the predefined presets for your passwords

    AppleID: 
    A preset respecting the many prerequisites Apple places on Apple ID passwords. 
    The preset also limits itself to symbols found on the iOS letter and number keyboards 
    (i.e. not the awkward to reach symbol keyboard)

    Default: 
    The default preset resulting in a password consisting of 3 random words of 
    between 4 and 8 letters with alternating case separated by a random character, 
    with two random digits before and after, and padded with two random characters front and back

    NTLM: 
    A preset for 14 character Windows NTLMv1 password. WARNING - only use this preset if you 
    have to, it is too short to be acceptably secure and will always generate entropy warnings 
    for the case where the config and dictionary are known.

    SecurityQ: 
    A preset for creating fake answers to security questions.

    Web16: 
    A preset for websites that insit passwords not be longer than 16 characters.

    Web32: 
    A preset for websites that allow passwords up to 32 characteres long.

    WiFi: 
    A preset for generating 63 character long WPA2 keys (most routers allow 64 characters, but some only 63, hence the odd length).

    XKCD: 
    A preset for generating passwords similar to the example in the original XKCD cartoon, 
    but with a dash to separate the four random words, and the capitalisation 
    randomised to add sufficient entropy to avoid warnings.

    .EXAMPLE
    PS C:\>Get-XKCDPassword
    honors#CHESTER#skirt!BROWSERS

    Running Get-XKCDPassword without any parameters specified will give you a password based on the defaults in Param()

    .EXAMPLE
    PS C:\>Get-XKCDPassword -NumberofWords 10 -MinimumWordLength 4 -MaximumWordLength 12 -CaseTransformation EveryOtherUpperLowerCase -SeparatorCharacters "-","!","@" -PaddingDigitsBefore 2 -PaddingDigitsAfter 2 -PaddingSymbols ".","," -PaddingSymbolsBefore 1 -PaddingSymbolsAfter 1
    .31evening@CASES!atlantic!EVOLUTION!using@SUNNY@banners@GRID@angola@CINCINNATI15.

    This example shows the output when all parameters are set

    .EXAMPLE 
    PS C:\>Get-XKCDPassword -Preset AppleID
    ?10FUZZY:FINDS-cottage55&

    Output using a predefined preset

    .LINK
    https://xkpasswd.net/
    https://xkcd.com/936/

    .NOTES
    Author: Richard Mikalsen (ricmik)
        
    This PowerShell function is inspired by the works of Bart Busschots and the https://xkpasswd.net/ web site.

    #>
    [CmdletBinding(DefaultParametersetName = 'Preset')]     
    Param(
        [string]
        $DictionaryPath = "$PSScriptRoot\..\sample_dict_EN.txt",
        [Parameter(ParameterSetName = 'CustomPassword')]
        [int]
        $NumberofWords = 3,
        [Parameter(ParameterSetName = 'CustomPassword')]
        [int]
        $MinimumWordLength,
        [Parameter(ParameterSetName = 'CustomPassword')]
        [int]
        $MaximumWordLength,
        [Parameter(ParameterSetName = 'CustomPassword')]
        [ValidateSet("FirstLetterUpperCase", "RandomUpperLowerCase", "EveryOtherUpperLowerCase", "LowerCase", "UpperCase", "None")]
        [String]
        $CaseTransformation = 'EveryOtherUpperLowerCase',
        [Parameter(ParameterSetName = 'CustomPassword')]
        [array]
        $SeparatorCharacters = @("!", "@", "$", "%", "^", "&", "*", "-", "_", "+", "=", ":", "|", "~", "?", "/", ".", ";"),
        [Parameter(ParameterSetName = 'CustomPassword')]
        [ValidateRange(0, 5)]
        [int]
        $PaddingDigitsBefore = 2,
        [Parameter(ParameterSetName = 'CustomPassword')]
        [ValidateRange(0, 5)]
        [int]
        $PaddingDigitsAfter = 2,
        [Parameter(ParameterSetName = 'CustomPassword')]
        [array]
        $PaddingSymbols = @("!", "@", "$", "%", "^", "&", "*", "-", "_", "+", "=", ":", "|", "~", "?", "/", ".", ";"),
        [Parameter(ParameterSetName = 'CustomPassword')]
        [ValidateRange(0, 5)]
        [int]
        $PaddingSymbolsBefore = 2,
        [Parameter(ParameterSetName = 'CustomPassword')]
        [ValidateRange(0, 5)]
        [int]
        $PaddingSymbolsAfter = 2,
        [Parameter(ParameterSetName = 'CustomPassword')]        
        [int]
        $PaddingToLength,
        [Parameter(ParameterSetName = 'Preset')]
        [ValidateSet("AppleID", "Default", "NTLM", "SecurityQ", "Web16", "Web32", "WiFi", "XKCD")]
        [string]
        $Preset

    )

    # Presets are defined here
    if ($Preset) {
        switch ($Preset) {
            AppleID {
                $NumberofWords = 3
                $MinimumWordLength = 5
                $MaximumWordLength = 7
                $CaseTransformation = "RandomUpperLowerCase"
                $SeparatorCharacters = @("-", ":", ".", ",")
                $PaddingDigitsBefore = 2
                $PaddingDigitsAfter = 2
                $PaddingSymbols = @("!", "?", "@", "&")
                $PaddingSymbolsBefore = 1
                $PaddingSymbolsAfter = 1
            }
            NTLM {
                $NumberofWords = 3
                $MinimumWordLength = 5
                $MaximumWordLength = 7
                $CaseTransformation = "FirstLetterUpperCase"
                $SeparatorCharacters = @("-", "+", "=", ".", "*", "_", "|", "~", ",")
                $PaddingDigitsBefore = 1
                $PaddingDigitsAfter = 0
                $PaddingSymbols = @("!", "@", "$", "%", "^", "&", "*", "+", "=", ":", "|", "~", "?")
                $PaddingSymbolsBefore = 0
                $PaddingSymbolsAfter = 1
            }
            SecurityQ {
                $NumberofWords = 6
                $MinimumWordLength = 4
                $MaximumWordLength = 8
                $CaseTransformation = "None"
                $SeparatorCharacters = @(" ")
                $PaddingDigitsBefore = 0
                $PaddingDigitsAfter = 0
                $PaddingSymbols = @(".", "!", "?")
                $PaddingSymbolsBefore = 0
                $PaddingSymbolsAfter = 1
            }
            Web16 {
                $NumberofWords = 3
                $MinimumWordLength = 4
                $MaximumWordLength = 4
                $CaseTransformation = "RandomUpperLowerCase"
                $SeparatorCharacters = @("-", "+", "=", ".", "*", "_", "|", "~", ",")
                $PaddingDigitsBefore = 0
                $PaddingDigitsAfter = 0
                $PaddingSymbols = @("!", "@", "$", "%", "^", "&", "*", "+", "=", ":", "|", "~", "?")
                $PaddingSymbolsBefore = 1
                $PaddingSymbolsAfter = 1
            }
            Web32 {
                $NumberofWords = 4
                $MinimumWordLength = 4
                $MaximumWordLength = 5
                $CaseTransformation = "EveryOtherUpperLowerCase"
                $SeparatorCharacters = @("-", "+", "=", ".", "*", "_", "|", "~", ",")
                $PaddingDigitsBefore = 2
                $PaddingDigitsAfter = 2
                $PaddingSymbols = @("!", "@", "$", "%", "^", "&", "*", "+", "=", ":", "|", "~", "?")
                $PaddingSymbolsBefore = 1
                $PaddingSymbolsAfter = 1
            }
            WiFi {
                $NumberofWords = 6
                $MinimumWordLength = 4
                $MaximumWordLength = 8
                $CaseTransformation = "RandomUpperLowerCase"
                $SeparatorCharacters = @("-", "+", "=", ".", "*", "_", "|", "~", ",")
                $PaddingDigitsBefore = 4
                $PaddingDigitsAfter = 4
                $PaddingSymbols = @("!", "@", "$", "%", "^", "&", "*", "+", "=", ":", "|", "~", "?")
                $PaddingSymbolsBefore = 0
                $PaddingToLength = 63
            }
            XKCD {
                $NumberofWords = 4
                $MinimumWordLength = 4
                $MaximumWordLength = 8
                $CaseTransformation = "RandomUpperLowerCase"
                $SeparatorCharacters = @("-")
                $PaddingDigitsBefore = 0
                $PaddingDigitsAfter = 0
                $PaddingSymbolsBefore = 0
                $PaddingSymbolsAfter = 0
            }
            Default {
                $NumberofWords = 3
                $MinimumWordLength = 4
                $MaximumWordLength = 8
                $CaseTransformation = "EveryOtherUpperLowerCase"
                $SeparatorCharacters = @("!", "@", "$", "%", "^", "&", "*", "-", "_", "+", "=", ":", "|", "~", "?", "/", ".", ";")
                $PaddingDigitsBefore = 2
                $PaddingDigitsAfter = 2
                $PaddingSymbols = @("!", "@", "$", "%", "^", "&", "*", "-", "_", "+", "=", ":", "|", "~", "?", "/", ".", ";")
                $PaddingSymbolsBefore = 2
                $PaddingSymbolsAfter = 2
            }
        }
    }
    

    # Build regex filter based on the MinimumWordLength and MaximumWordLength parameters
    if ($MinimumWordLength -gt 0 -and $MaximumWordLength -gt 0) { $regexmatch = "^\w{$MinimumWordLength,$MaximumWordLength}$" }
    elseif ($MinimumWordLength -ge 1 -and $MaximumWordLength -le 0) { $regexmatch = "^\w{$MinimumWordLength,}$" }
    elseif ($MinimumWordLength -le 0 -and $MaximumWordLength -ge 1) { $regexmatch = "^\w{1,$MaximumWordLength}$" }
    else { $regexmatch = "^\w+$" }
   
    # Get content from the dictionary - select only words within the word length boundaries
    [array]$wordlist = @()  
    Try { 
        $wordlist = (Select-String -Path $DictionaryPath -Pattern $regexmatch -ErrorAction Stop).Line
    } Catch [System.Management.Automation.ItemNotFoundException] {
        $error
        Throw "Could not find dictionary file. $($_.Exception.Message)"
    } Catch {
        Throw $_
    }
    Write-Debug "Dictionary search result length: $($wordlist.Length)"
    
    # Throw an exception if the search results from the dictionary contains one or less words
    if($wordlist.Length -lt $NumberofWords) {
        Throw "The dictionary search result was empty. Please try to adjust the MinimumWordLength and MaximumWordLength parameters."
    }

    # Fetch the amount of words needed based on the $NumberofWords variable
    $words = @() 
    for ($i = 0; $i -lt $NumberofWords; $i++) {
        $rngnum = Get-CryptoRandom -Minimum 0 -Maximum $wordlist.Length
        $words += $wordlist[$rngnum]
    }

    # Transform word casing
    switch ($CaseTransformation) {
        "FirstLetterUpperCase" {
            for ($i = 0; $i -lt $words.Length; $i++) {
                $words[$i] = (Get-Culture).TextInfo.ToTitleCase($words[$i])
            }
        }
        "RandomUpperLowerCase" { 
            for ($i = 0; $i -lt $words.Length; $i++) {
                if ((Get-CryptoRandom -Minimum 0 -Maximum 2) -eq 1) {
                    $words[$i] = $words[$i].ToUpper()
                }
            }
        }
        "EveryOtherUpperLowerCase" {
            for ($i = 0; $i -lt $words.Length; $i++) {
                # Check if $i is an odd number, then uppercase that word
                if ($i % 2) {
                    $words[$i] = $words[$i].ToUpper()
                }
                
            }
        }
        "LowerCase" {
            for ($i = 0; $i -lt $words.Length; $i++) {
                $words[$i] = $words[$i].ToLower()
            }
        }
        "UpperCase" {
            for ($i = 0; $i -lt $words.Length; $i++) {
                $words[$i] = $words[$i].ToUpper()
            }
        }
        Default {
            # No transformation
        }
    }

    # Start building the password
    $passwordsource = @()

    if ($SeparatorCharacters -ne "None") {
        # Get a random separator character to be used in the password
        $rngnum = Get-CryptoRandom -Minimum 0 -Maximum ($SeparatorCharacters.Length)
        $randseparator = $SeparatorCharacters[$rngnum]
    }
    if ($PaddingSymbols) {
        # Get a random padding symbol to be used in the password
        $rngnum = Get-CryptoRandom -Minimum 0 -Maximum ($PaddingSymbols.Length)
        $randpaddingsymbol = $PaddingSymbols[$rngnum]
    }
    # Padding at the beginning of the password
    if ($PaddingSymbolsBefore) {
        for ($i = 0; $i -lt $PaddingSymbolsBefore; $i++) {
            $passwordsource += $randpaddingsymbol
        }
    }
    if ($PaddingDigitsBefore) {
        $rngnum = Get-CryptoRandom -Minimum 99999
        $passwordsource += $rngnum.ToString().SubString(0, $PaddingDigitsBefore)
        # If separator characters are used, add the separator character before the first word
        if ($SeparatorCharacters -ne "None") {
            $passwordsource += $randseparator
        }
    }

    # Add the words and separators
    if ($SeparatorCharacters -ne "None") {
        for ($i = 0; $i -lt $words.Length; $i++) {
            $passwordsource += $words[$i]
            # Do not add the separator if this is the last word
            if ($i -lt $words.Length - 1) {
                $passwordsource += $randseparator
            }
        }
    } else {
        for ($i = 0; $i -lt $words.Length; $i++) {
            $passwordsource += $words[$i]
        }
    }

    # Padding at the end of the password
    if ($PaddingDigitsAfter) {
        # If separator characters are used, add the separator character after the last word
        if ($SeparatorCharacters -ne "None") {
            $passwordsource += $randseparator
        }
        $rngnum = Get-CryptoRandom -Minimum 99999
        $passwordsource += $rngnum.ToString().SubString(0, $PaddingDigitsAfter)
    }
    if ($PaddingSymbolsAfter) {
        for ($i = 0; $i -lt $PaddingSymbolsAfter; $i++) {
            $passwordsource += $randpaddingsymbol
        }
    }
    if ($PaddingToLength) {
        $currentpasswordlength = ($passwordsource | Measure-Object -Character).Characters
        for ($i = $currentpasswordlength; $i -lt $PaddingToLength; $i++) {
            $passwordsource += $randpaddingsymbol
        }
    }


    $password = -join $passwordsource
    return $password
    
    Remove-Variable -Name wordlist, words, password, passwordsource
}
 