$Module = "$PSScriptRoot\..\SWAD.psm1"
Remove-Module -Name SWAD -Force -ErrorAction SilentlyContinue
Import-Module -Name $Module -Force -ErrorAction Stop

InModuleScope SWAD {
    
    Describe 'New-SWRandomPassword' {
        $InputStrings = @('abcdefghijkmnopqrstuvwxyz', 'ABCEFGHJKLMNPQRSTUVWXYZ', '23456789', '!"#%&')
        It 'Generates a password of fixed lenght 8' {
            $Password = New-SWRandomPassword -PasswordLength 8 -InputStrings $InputStrings
            $InputStrings | ForEach-Object {
                $Password | Should MatchExactly "[$($_)]+"
            }
            $Password.Length | Should Be 8
        }
        It 'Generates a password of random lenght' {
            $Min = $InputStrings.Count
            $Max = $InputStrings.Count*2
            $Password = New-SWRandomPassword -MinPasswordLength $Min -MaxPasswordLength $Max -InputStrings $InputStrings
            $InputStrings | ForEach-Object {
                $Password | Should MatchExactly "[$($_)]+"
            }
            ($Password.Length -ge $Min) | Should Be $true
            ($Password.Length -le $Max) | Should Be $true
        }

        It 'Generates a password of length 1' {
            $Password = New-SWRandomPassword -PasswordLength 1 -InputStrings $InputStrings
            $Password | Should MatchExactly "[$(-join$InputStrings)]"
            $Password.Length | Should be 1
        }

        It 'Generates unique passwords' {
            $Passwords = New-SWRandomPassword -PasswordLength 8 -InputStrings $InputStrings -Count 100
            $Passwords.Count | Should be 100
            ($Passwords | Select-Object -Unique).Count | Should be 100
        }
    }

    Describe ''
}
