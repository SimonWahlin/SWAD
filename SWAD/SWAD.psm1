$PSDefaultParameterValues.Clear()
$GroupMembershipStart = ''

function New-SWRandomPassword 
{
    <#
    .Synopsis
       Generates one or more complex passwords designed to fulfill the requirements for Active Directory
    .DESCRIPTION
       Generates one or more complex passwords designed to fulfill the requirements for Active Directory
    .EXAMPLE
       New-SWRandomPassword
       C&3SX6Kn

       Will generate one password with a length between 8  and 12 chars.
    .EXAMPLE
       New-SWRandomPassword -MinPasswordLength 8 -MaxPasswordLength 12 -Count 4
       7d&5cnaB
       !Bh776T"Fw
       9"C"RxKcY
       %mtM7#9LQ9h

       Will generate four passwords, each with a length of between 8 and 12 chars.
    .EXAMPLE
       New-SWRandomPassword -InputStrings abc, ABC, 123 -PasswordLength 4
       3ABa

       Generates a password with a length of 4 containing atleast one char from each InputString
    .EXAMPLE
       New-SWRandomPassword -InputStrings abc, ABC, 123 -PasswordLength 4 -FirstChar abcdefghijkmnpqrstuvwxyzABCEFGHJKLMNPQRSTUVWXYZ
       3ABa

       Generates a password with a length of 4 containing atleast one char from each InputString that will start with a letter from 
       the string specified with the parameter FirstChar
    .OUTPUTS
       [String]
    .NOTES
       Written by Simon Wåhlin, blog.simonw.se
       I take no responsibility for any issues caused by this script.
    .FUNCTIONALITY
       Generates random passwords
    .LINK
       http://blog.simonw.se/powershell-generating-random-password-for-active-directory/
   
    #>
    [CmdletBinding(DefaultParameterSetName='FixedLength',ConfirmImpact='None')]
    [OutputType([String])]
    Param
    (
        # Specifies minimum password length
        [Parameter(Mandatory=$false,
                   ParameterSetName='RandomLength')]
        [ValidateScript({$_ -gt 0})]
        [Alias('Min')] 
        [int]$MinPasswordLength = 8,
        
        # Specifies maximum password length
        [Parameter(Mandatory=$false,
                   ParameterSetName='RandomLength')]
        [ValidateScript({
                if($_ -ge $MinPasswordLength){$true}
                else{Throw 'Max value cannot be lesser than min value.'}})]
        [Alias('Max')]
        [int]$MaxPasswordLength = 12,

        # Specifies a fixed password length
        [Parameter(Mandatory=$false,
                   ParameterSetName='FixedLength')]
        [ValidateRange(1,2147483647)]
        [int]$PasswordLength = 8,
        
        # Specifies an array of strings containing charactergroups from which the password will be generated.
        # At least one char from each group (string) will be used.
        [String[]]$InputStrings = @('abcdefghijkmnpqrstuvwxyz', 'ABCEFGHJKLMNPQRSTUVWXYZ', '23456789', '!"#%&'),

        # Specifies a string containing a character group from which the first character in the password will be generated.
        # Useful for systems which requires first char in password to be alphabetic.
        [String] $FirstChar,
        
        # Specifies number of passwords to generate.
        [ValidateRange(1,2147483647)]
        [int]$Count = 1
    )
    Begin {
        Function Get-Seed{
            # Generate a seed for randomization
            $RandomBytes = New-Object -TypeName 'System.Byte[]' 4
            $Random = New-Object -TypeName 'System.Security.Cryptography.RNGCryptoServiceProvider'
            $Random.GetBytes($RandomBytes)
            [BitConverter]::ToUInt32($RandomBytes, 0)
        }
    }
    Process {
        For($iteration = 1;$iteration -le $Count; $iteration++){
            $Password = @{}
            # Create char arrays containing groups of possible chars
            [char[][]]$CharGroups = $InputStrings

            # Create char array containing all chars
            $AllChars = $CharGroups | ForEach-Object {[Char[]]$_}

            # Set password length
            if($PSCmdlet.ParameterSetName -eq 'RandomLength')
            {
                if($MinPasswordLength -eq $MaxPasswordLength) {
                    # If password length is set, use set length
                    $PasswordLength = $MinPasswordLength
                }
                else {
                    # Otherwise randomize password length
                    $PasswordLength = ((Get-Seed) % ($MaxPasswordLength + 1 - $MinPasswordLength)) + $MinPasswordLength
                }
            }

            # If FirstChar is defined, randomize first char in password from that string.
            if($PSBoundParameters.ContainsKey('FirstChar')){
                $Password.Add(0,$FirstChar[((Get-Seed) % $FirstChar.Length)])
            }
            # Randomize one char from each group
            Foreach($Group in $CharGroups) {
                if($Password.Count -lt $PasswordLength) {
                    $Index = Get-Seed
                    While ($Password.ContainsKey($Index)){
                        $Index = Get-Seed                        
                    }
                    $Password.Add($Index,$Group[((Get-Seed) % $Group.Count)])
                }
            }

            # Fill out with chars from $AllChars
            for($i=$Password.Count;$i -lt $PasswordLength;$i++) {
                $Index = Get-Seed
                While ($Password.ContainsKey($Index)){
                    $Index = Get-Seed                        
                }
                $Password.Add($Index,$AllChars[((Get-Seed) % $AllChars.Count)])
            }
            Write-Output -InputObject $(-join ($Password.GetEnumerator() | Sort-Object -Property Name | Select-Object -ExpandProperty Value))
        }
    }
}

<#
.Synopsis
   Format an ldap filter with linebreaks and indenting
   for a more readable format.

   To revert to valid ldap filter, use $filter -replace '\n\s*',''
.DESCRIPTION
   Ldap filters can be hard to read when they get more advanced.
   This script will reformat them for better readability.
.EXAMPLE
   
   $filter = '(&(objectCategory=person)(objectClass=user)(!(userAccountControl
   :1.2.840.113556.1.4.803:=2))(|(accountExpires=0)(accountExpires=9223372036854775
   807))(userAccountControl:1.2.840.113556.1.4.803:=65536))'
   
   Show-SWldapFilter -ldapFilter $filter
   (&
       (objectCategory=person)
       (objectClass=user)
       (!
           (userAccountControl:1.2.840.113556.1.4.803:=2)
       )
       (|
           (accountExpires=0)
           (accountExpires=9223372036854775807)
       )
       (userAccountControl:1.2.840.113556.1.4.803:=65536)
   )

.NOTES
   Written by Simon Wåhlin, blog.simonw.se
#>
Function Show-SWADldapFilter 
{
    [Cmdletbinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        [String[]]
        $ldapFilter
    )
    Begin
    { 
        $stringBuilder = New-Object -TypeName System.Text.StringBuilder
        $Tab = '    '
        function New-IndentedText ($Text,$NumIndents) 
        {
            "`n$('    ' * $NumIndents)$Text"
        }
    }
    Process
    {
        Foreach ($String in $ldapFilter)
        {
            $null = $stringBuilder.Clear()
            $Indent = 0
            
            $null = $stringBuilder.Append($String[0])
            
            for( $i=1; $i -lt $String.Length; $i++ )
            {
                $Char = $String[$i]
                switch -Regex ($String.Substring( ($i-1),2 ))
                {
                    "\([|&!]"
                    {
                        $Indent++
                        $null = $stringBuilder.Append($Char)
                        $null = $stringBuilder.Append($(New-IndentedText "" $Indent))
                    }
                    "\)\("
                    {
                        $null = $stringBuilder.Append($(New-IndentedText $Char $Indent))
                    }
                    "\)\)"
                    {
                        $Indent--
                        $null = $stringBuilder.Append($(New-IndentedText $Char $Indent))
                    }

                    default
                    {
                       $null = $stringBuilder.Append($Char)
                    }
                }
            }
            if($Indent -lt 0)
            {
                Throw "Invalid ldapFilter!"
            }
            $stringBuilder.ToString()
        }
    }
    End
    {
        Remove-Variable -Name StringBuilder -ErrorAction SilentlyContinue
    }
}

<#
.Synopsis
   Get Bitlocker recovery key for computer.
.DESCRIPTION
   Will get all Bitlocker recovery keys for specified computer(s)
.EXAMPLE
   Get-SWADBitlockerRecoveryPassword -Name 'Client04'
.NOTES
   Written by Simon Wåhlin, blog.simonw.se
#>
Function Get-SWADBitlockerRecoveryPassword
{
    [cmdletbinding()]
    Param(
        [Parameter(
            Mandatory         = $true,
            Position          = 0,
            ValueFromPipeline = $true
        )]
        [String[]]
        $Name,

        [Parameter()]
        [String]
        $Server
    )
    Process
    {
        Foreach($objName in $Name)
        {
            $Params = @{
                Identity = $objName
            }
            if($PSBoundParameters.ContainsKey('Server'))
            {
                $Params.Add('Server',$Server)
            }
            $DN = Get-ADComputer @Params | Select -ExpandProperty Distinguishedname
            Get-ADObject -SearchBase $DN -SearchScope Subtree -LDAPFilter "(ObjectClass=msFVE-RecoveryInformation)" -Properties msFVE-RecoveryPassword, Created | 
                Select-Object @{n='Computer';e={($_.DistinguishedName -split ',')[1] -replace '^CN=',''}},
                @{n='RecoveryPassword';e={$_.'msFVE-RecoveryPassword'}}, Created
        }
    }
}

<#
.Synopsis
   Get all groups an object is member of recursively.
.DESCRIPTION
   Get all groups an object is member of recursively.

   Useful to answear the question:
   Which group is X a member of?
.EXAMPLE
   Get-SWADGroupMembership -Identity '
.NOTES
   Written by Simon Wåhlin, blog.simonw.se
#>
function Get-NestedGroup 
{
    [cmdletbinding()]
    param(
        [Parameter(
            Mandatory         = $true,
            Position          = 0,
            ValueFromPipeline = $true
        )]
        [string]
        $Identity,
		
        [Parameter()]
        [String[]]
        $Properties = 'Name',
		
		[Parameter()]
		[String]
		$Server,

        [Parameter(
            ParameterSetName='NestedOutput'
        )]
		[Switch]
		$NestOutput

    )
	Begin
	{
		$Params = @{
			Properties  = $Properties + @('memberOf') | Select-Object -Unique
            ErrorAction = 'Stop'
		}
		if($PSBoundParameters.ContainsKey('Server'))
		{
			$Params.Add('Server',$Server)
		}
	}
    Process
    {
		Try
        {
            $Group = Get-ADGroup -Identity $Identity @Params
            $ParentInvocation = Get-Variable -Name MyInvocation -Scope 1 -ValueOnly
            if($ParentInvocation.MyCommand.Name -ne $MyInvocation.MyCommand.Name)
            {
                Write-Verbose -Message 'Not recursive call, set start and recurse.'
                $Script:NestedGroupStart = $Group.distinguishedName
            }
            else
            {
                Write-Verbose -Message 'Recursive call, check for nested loop.'
                if($Script:NestedGroupStart -like $Group.distinguishedName)
                {
                    $PreviousGroup = Get-Variable -Name Group -Scope 1 -ValueOnly
                    Write-Warning -Message ('Nested loop detected in: {0}' -f $Group.distinguishedName)
                    Write-Warning -Message ('Parent group: {0}' -f $PreviousGroup.distinguishedName)
                    Throw ('Nested group loop detected in group: {0}' -f $Group.distinguishedName)
                }
            }
            Write-Verbose -Message 'No loop detected, write output.'
            
            [System.Void]$PSBoundParameters.Remove('Identity')
            
            $Result = New-Object -TypeName psobject
            $Properties | 
                foreach {
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name $_ -Value $Group.psobject.Properties[$_].Value
                }
            if($NestOutput)
            {
                Add-Member -InputObject $Result -MemberType NoteProperty -Name MemberOf -Value ($Group.MemberOf | Get-NestedGroup @PSBoundParameters)
                Write-Output -InputObject $Result
            }
            else
            {
                Write-Output -InputObject $Result
                $Group.MemberOf | Get-NestedGroup @PSBoundParameters
            }
        }
        Catch
        {
            Throw   
        }
    }
}

function Get-SWADGroupMembership 
{
    [cmdletbinding()]
    param(
        [Parameter(
            Mandatory         = $true,
            Position          = 0,
            ValueFromPipeline = $true
        )]
        [string]
        $Identity,
		
        [Parameter()]
        [String[]]
        $Properties,
		
		[Parameter()]
		[String]
		$Server,

        [Parameter()]
		[Switch]
		$NestOutput
    )
	Begin
	{
		$Params = @{
			Properties  = @('memberOf') + $Properties | Select-Object -Unique
            ErrorAction = 'Stop'
		}
		if($PSBoundParameters.ContainsKey('Server'))
		{
			$Params.Add('Server',$Server)
		}
	}
    Process
    {
		Try
		{
		 	$Object = Get-ADUser -Identity $Identity @Params
	    }
        Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
        {
            Try
            {
                $Object = Get-ADGroup -Identity $Identity @Params
            }
            Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
            {
                Try
                {
                    $Object = Get-ADComputer -Identity $Identity @Params
                }
                Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
                {
                    Try
                    {
                        $Object = Get-ADServiceAccount -Identity $Identity @Params
                    }
                    Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
                    {
                        Try
                        {
                            $Object = Get-ADObject -Identity $Identity @Params
                        }
                        Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
                        {
                            Throw
                        }
                    }
                }
            }
        }
        Catch
        {
            Throw
        }
        [System.Void]$PSBoundParameters.Remove('Identity')
        $Object.MemberOf | Get-NestedGroup @PSBoundParameters
    }
}

function Get-SWADGroupMembershipReport
{
    [cmdletbinding()]
    param(
        [Parameter(
            Mandatory         = $true,
            Position          = 0,
            ValueFromPipeline = $true
        )]
        [string]
        $Identity,

        [Parameter()]
        [ValidateSet('Name','distinguishedName','sAMAccountName')]
        [string]
        $Property = 'Name',
        
        [Parameter()]
		[String]
		$Server
    )
	Begin
	{
		$ObjParams = @{
			Properties  = $Property#,'memberof','objectClass'
            ErrorAction = 'Stop'
		}
		$ServerParam = @{}
        if($PSBoundParameters.ContainsKey('Server'))
        {
            $ServerParam.Server = $Server
        }
        $Domain = Get-ADDomain @ServerParam
	}
    Process
    {
        Try
        {
            $Result = Get-SWADGroupMembership -Identity $Identity @ObjParams @ServerParam -NestOutput
            $Result | ConvertTo-StringTree -NameProperty $Property -ChildProperty 'MemberOf'
        }
        Catch
        {
            Throw   
        }
    }
}

Function ConvertTo-StringTree
{
    [CmdletBinding(
        DefaultParameterSetName = 'NoType'
    )]
    [OutputType([String])]
    Param(
        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'Type',
            ValueFromPipeline = $true
        )]
        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'NoType',
            ValueFromPipeline = $true
        )]
        [object[]]
        $InputObject,

        [Parameter(
            #Mandatory = $true,
            ParameterSetName = 'Type'
        )]
        [Parameter(
            #Mandatory = $true,
            ParameterSetName = 'NoType'
        )]
        [String]
        $NameProperty,

        [Parameter(
            #Mandatory = $true,
            ParameterSetName = 'Type'
        )]
        [Parameter(
            #Mandatory = $true,
            ParameterSetName = 'NoType'
        )]
        [String]
        $ChildProperty,

        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'Type'
        )]
        [String]
        $TypeProperty = 'ObjectClass',

        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'Type'
        )]
        [HashTable]
        $TypeDictionary,

        [Parameter(
            ParameterSetName = 'Type'
        )]
        [Parameter(
            ParameterSetName = 'NoType'
        )]
        [string]
        $Padding = ""
    )
    Begin
    {
        $Prefix     = '{0}{1} ' -f ([char]0x251C),([char]0x2500)
	$PrefixLast = '{0}{1} ' -f ([char]0x2514),([char]0x2500)
	$Spacer     = '{0}  ' -f ([char]0x2502)
	$SpacerLast = '   '
	$Out        = ''

        $StandardNames = @('Name')
        $StandardChild = @('Members','MemberOf','Children')
    }
    Process
    {
        if(-Not($PSBoundParameters.ContainsKey('NameProperty')))
        {
            Foreach ($Name in $StandardNames)
            {
                if(($InputObject | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name) -contains $Name)
                {
                    $NameProperty = $Name
                    break
                }
            }
            if([String]::IsNullOrEmpty($NameProperty))
            {
                Throw 'No Name property found!'
            }

        }

        if(-Not($PSBoundParameters.ContainsKey('ChildProperty')))
        {
            Foreach ($Name in $StandardChild)
            {
                if(($InputObject | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name) -contains $Name)
                {
                    $ChildProperty = $Name
                    break
                }
            }
        }

        $ParentInvocation = Get-Variable -Name MyInvocation -Scope 1 -ValueOnly

        $Last = $InputObject.Count-1
        for($i = 0; $i -le $Last; $i++)
        {
            $ResultRow = '{0}{1}{2}{3}' -f @(
                $Padding,
                $(
                    if($ParentInvocation.MyCommand.Name -eq $MyInvocation.MyCommand.Name)
                    {
                        if($i-eq$last){$PrefixLast}else{$Prefix}
                    }
                    else
                    {
                        ''
                    }
                ),
                $(
                    if($PSCmdlet.ParameterSetName -eq 'Type')
                    {
                        $Char = $InputObject[$i] | foreach -Process $([scriptblock]::Create($TypeDictionary[$InputObject[$i].$TypeProperty]))
                        "$Char"
                    }
                    else {''}
                ),
                $InputObject[$i].$NameProperty
            )

            Write-Output -InputObject $ResultRow

            if($InputObject[$i].$ChildProperty -ne $null)
            {
                [System.Void]$PSBoundParameters.Remove('InputObject')
                if($i -eq $Last)
                {
                    [System.Void]($PSBoundParameters['Padding'] = $Padding + $SpacerLast)
                }
                else
                {
                    [System.Void]($PSBoundParameters['Padding'] = $Padding + $Spacer)
                }
                ConvertTo-StringTree -InputObject $InputObject[$i].$ChildProperty @PSBoundParameters
            }
        }
    }    
}

<#
.Synopsis
   Will return the count of items in the DFSR-backlog for each replicated folder specified.
.DESCRIPTION
   Will return the count of items in the DFSR-backlog for each replicated folder specified.
.EXAMPLE
   Get-SWDFSRBacklog -Threshold 50

   Will return numbor of items in the DFSR backlog for each folder that has a backlog of more than 50 items.
.EXAMPLE
   Get-SWDFSRBacklog -FolderName "Folder1", "Folder2"

   RGName : Folder1
   RFName : Folder1
   SMem   : Server01
   RMem   : Server02
   Count  : 0

   RGName : Folder1
   RFName : Folder1
   SMem   : Server02
   RMem   : Server01
   Count  : 0

   RGName : Folder2
   RFName : Folder1
   SMem   : Server01
   RMem   : Server02
   Count  : 0

   RGName : Folder2
   RFName : Folder1
   SMem   : Server02
   RMem   : Server01
   Count  : 0

   Will return the number of items in the backlog for the replicated folders Folder1 and Folder2.
 .LINK
   http://blog.simonw.se
#>
Function Get-SWDFSRBacklog
{
    [Cmdletbinding()]
    Param
    (
        [String]
        $DomainName = (Select-Object -InputObject $([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()) -ExpandProperty Name),
        [String[]]
        $FolderName,
        [Int]
        $Threshold = 0
    )
    Begin
    {
        $Param = @{
            DomainName = $DomainName
            ErrorAction = 'Stop'
        }
        If( $PSBoundParameters.ContainsKey('FolderName') )
        {
            $Param.FolderName = $FolderName
        }
        $Folders = Get-DfsReplicatedFolder @Param
    }
    Process
    {
        foreach ($Folder in $Folders)
        {
            Write-Verbose -Message "Processing replicated folder $($Folder.FolderName)"
            $Members = $(Get-DfsrMember -GroupName $Folder.GroupName)
            foreach($Member in $Members)
            {
                $Partners = $Members | Where {$_ -ne $Member}
                Foreach ($Partner in $Partners)
                {
                    Write-Verbose -Message "Querying backlog between $($Member.ComputerName) and $($Partner.ComputerName)"
                    Try
                    {
                        # Read Verbose stream and ignore output stream
                        $VerboseMessage = $($Null = Get-DfsrBacklog -GroupName $Folder.GroupName -FolderName $Folder.FolderName -SourceComputerName $Member.ComputerName -DestinationComputerName $Partner.ComputerName -ErrorAction Stop -Verbose) 4>&1
                    }
                    Catch
                    {
                        Write-Warning -Message "Failed to query backlog between $($Member.ComputerName) and $($Partner.ComputerName)"
                        Continue
                    }
                    if ($VerboseMessage -Like "No backlog for the replicated folder named `"$($Folder.FolderName)`"")
                    {
                        $BacklogCount = 0
                    }
                    else
                    {
                        Try
                        {
                            $BacklogCount = [int]$($VerboseMessage -replace "The replicated folder has a backlog of files. Replicated folder: `"$($Folder.FolderName)`". Count: (\d+)",'$1')
                        }
                        Catch
                        {
                            Write-Warning -Message $_.Exception.Message
                            Continue
                        }
                    }
                    if( $BacklogCount -ge $Threshold )
                    {
                        [PSCustomObject]@{
                            RGName = $Folder.GroupName
                            RFName = $Folder.FolderName
                            SMem = $Member.ComputerName
                            RMem = $Partner.ComputerName
                            Count = $BacklogCount
                        }
                    }
                    else
                    {
                        Write-Verbose -Message "Backlogcount of $BacklogCount is below the threshold: $Threshold between $($Member.ComputerName) and $($Partner.ComputerName)"
                    }
                }
            }
        }
    }
}

Function Get-SWADNetlogonLog 
{
    [Cmdletbinding()]
    Param
    (
        [Parameter()]
        [Int]
        $NumLines = 100,
        [Parameter(ValueFromPipeline)]
        [String[]]
        $DomainControllers = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).DomainControllers.Name
    )
    Process
    {
        Foreach($DC in $DomainControllers)
        {
            $NetLogonPath = "\\$DC\admin$\debug\netlogon.log"
            if(Test-Path -Path $NetLogonPath)
            {
                Get-Content -Path $NetLogonPath -Tail $NumLines
            }
            else
            {
                Write-Error -Message "Failed to access $NetlogonPath" -Category ConnectionError
            }
        }
    }
}

<#
.Synopsis
   Retrieves last (n) lines from netlogon.log from each specified domain 
   controller and returns a report on missing subnets.
.DESCRIPTION
   Retrieves last (n) lines from netlogon.log from each specified domain 
   controller and returns a report on missing subnets.

   Converts each entry to a PSCustomObject containing Client Name, IP Address
   and a TimeStamp.
.EXAMPLE 
   Get-MissingSubnets.ps1

   Will use default values for number of lines to read from each log file and 
   try to retrieve the logs from all domain controllers in the current domain.
   Will also assume that timestamping is enabled in netlogon.log

   Returns a list of IPAddresses not part of any defined subnet in AD
.EXAMPLE
   Get-MissingSubnets.ps1 -IncludeTimestamp $false

   Will use default values for number of lines to read from each log file and 
   try to retrieve the logs from all domain controllers in the current domain.
   Will ignore any timestamps in netlogon.log

   Returns a list of IPAddresses not part of any defined subnet in AD
#>
Function Get-SWADMissingSubnets
{
    Param
    (
        # Defines number of lines to read from netlogon.log on each domain controller.
        [Parameter()]
        [Int]
        $NumLines = 100,
        # Defines which domain controllers to read netlogon.log from. If not used,
        # all domain controllers in current domain is used.
        [Parameter()]
        [String[]]
        $DomainControllers = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).DomainControllers.Name,
        # Specified if timestamps should be read from netlogon.log or not.
        # If timestamping in netlogon.log is disabled on any domain controller, 
        # set this to $false.
        [Parameter()]
        [Switch]
        $IncludeTimestamp = $false
    )

            $Param = @{
    NumLines = $NumLines
    DomainControllers = $DomainControllers
    }

    Get-SWADNetlogonLog @Param | FindSWADMissingSubnetsEntry -IncludeTimestamp $IncludeTimestamp | Group -Property IPAddress | Foreach { $_.Group | Sort TimeStamp | Select -Last 1 } | Sort-Object -Property IPAddress
}

<#
.Synopsis
   Collects Lockout Events from current domain
.DESCRIPTION
   Users locking out their accounts can be hard to troubleshoot.
   This cmdlet will collect recent lockout events from the Security-log
   on the Domain Controller currently holdning the PDC-Emulator FSMO Role.

   Will show when the lockout occured, which account that got locked out
   and from which machine the lockout occured.

   If the Computer name is an email server, the lockout was most probably
   caused by a device trying to sync emails.
.EXAMPLE
   Get-SWLockoutEvents
.EXAMPLE
   Get-SWLockoutEvents -MaxEvents 10

   Collects the last 10 lockout events.
.NOTES
   Script written by Simon Wåhlin

   Published to blog.simonw.se

   Disclaimer:
    This script is provided "AS IS" with no warranties, confers no rights and 
    is not supported by the author.
.LINK
   http://blog.simonw.se
#>
Function Get-SWADLockoutEvents 
{
[Cmdletbinding()]
Param
(
    [Int64]
    $MaxEvents
)
    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $Xpath = '*[System[(EventID=4740)]]'
    $Params = @{
        LogName = 'Security'
        ComputerName = $PDC
        FilterXPath = $Xpath
        ErrorAction = 'Stop'
    }
    if($MaxEvents -gt 0)
    {
        $Params['MaxEvents'] = $MaxEvents
    }

    Get-WinEvent @Params |
        Select-Object TimeCreated,
            @{n='UserName';e={$_.Properties[0].Value}},
            @{n='SourceComputer';e={$_.Properties[1].Value}}
}

Function Get-SWADSchemaInfo
{
    Get-ADObject (Get-ADRootDSE).Schemanamingcontext -Properties Created, Modified, objectVersion, fSMORoleOwner |
        Select-Object -Property DistinguishedName, Created, Modified,
            @{n='SchemaVersion';e={$_.objectVersion}},
            fSMORoleOwner
}

<#
    .Synopsis
        Generates a table with phonetic spelling from a collection of characters
    .DESCRIPTION
        Generates a table with phonetic spelling from a collection of characters
    .EXAMPLE
        "gjIgsj" | Get-Phonetic

        Input text: gjIgsj

        Char Phonetic
        ---- --------
            g golf    
            j juliett 
            I INDIA   
            g golf    
            s sierra  
            j juliett 
       
    .OUTPUTS
        [String]
    .NOTES
        Written by Simon Wåhlin, blog.simonw.se
        I take no responsibility for any issues caused by this script.
#>
function Get-SWPhonetic 
{
    Param (
        # List of characters to translate to phonetic alphabet
        [Parameter(Mandatory=$true,ValueFromPipeLine=$true)]
        [Char[]]$Char,
        # Hashtable containing a char as key and phonetic word as value
        [HashTable]$PhoneticTable = @{
            'a' = 'alpha'   ;'b' = 'bravo'   ;'c' = 'charlie';'d' = 'delta';
            'e' = 'echo'    ;'f' = 'foxtrot' ;'g' = 'golf'   ;'h' = 'hotel';
            'i' = 'india'   ;'j' = 'juliett' ;'k' = 'kilo'   ;'l' = 'lima' ;
            'm' = 'mike'    ;'n' = 'november';'o' = 'oscar'  ;'p' = 'papa' ;
            'q' = 'quebec'  ;'r' = 'romeo'   ;'s' = 'sierra' ;'t' = 'tango';
            'u' = 'uniform' ;'v' = 'victor'  ;'w' = 'whiskey';'x' = 'x-ray';
            'y' = 'yankee'  ;'z' = 'zulu'    ;'0' = 'Zero'   ;'1' = 'One'  ;
            '2' = 'Two'     ;'3' = 'Three'   ;'4' = 'Four'   ;'5' = 'Five' ;
            '6' = 'Six'     ;'7' = 'Seven'   ;'8' = 'Eight'  ;'9' = 'Niner';
            '.' = 'Point'   ;'!' = 'Exclamationmark';'?' = 'Questionmark';
        }
    )
    Process {
        $Result = Foreach($Character in $Char) {
            if($PhoneticTable.ContainsKey("$Character")) {
                if([Char]::IsUpper([Char]$Character)) {
                    [PSCustomObject]@{
                        Char = $Character;Phonetic = $PhoneticTable["$Character"].ToUpper()
                    }
                }
                else {
                    [PSCustomObject]@{
                        Char = $Character;Phonetic = $PhoneticTable["$Character"].ToLower()
                    }
                }
            }
            else {
                [PSCustomObject]@{
                    Char = $Character;Phonetic = $Character
                }
            }
            
        }
        "`n{0}`n{1}" -f ('Input text: {0}'-f-join$Char), ($Result | Format-Table -AutoSize | Out-String)
    }
}

<#
.Synopsis
   Reset the password for specified user to a random password.
.DESCRIPTION
   Uses the functions New-SWRandomPassword and Get-Phonetic to generate a random
   password with specified length, reset the specified user's password and display
   the new password with phonetic spelling.

   Will unlock specified user and unless the parameter -NoChange is specified the user
   will have to change its password on next logon.
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Reset-SWADPassword
{
    [cmdletbinding(SupportsShouldProcess=$true,ConfirmImpact='Medium')]
    param(
        # Identity of user that should have their pasword reset
        [Parameter(Mandatory=$true)]
        [Alias('DistinguishedName')]
        [String]$Identity,

        # Length of password that will be generated
        [ValidateRange(1,[int]::MaxValue)]
        [int]$Length = 8,

        # Specifies an array of strings containing charactergroups from which the password will be generated.
        # At least one char from each group (string) will be used.
        [String[]]$InputStrings = @('abcdefghijkmnopqrstuvwxyz', 'ABCEFGHJKLMNPQRSTUVWXYZ', '23456789', '!"#%&'),

        # Specifies that the user will not have to change their password on next logon
        [Switch]$NoChange
    )
    Try
    {
        $Password = New-SWRandomPassword -PasswordLength $Length -InputStrings $InputStrings
        $SecPaswd = ConvertTo-SecureString -String $Password -AsPlainText -Force
        if($PSCmdlet.ShouldProcess("`n$DistinguishedName",'Reset password'))
        {
            $ADUser = Set-ADAccountPassword -Reset -NewPassword $SecPaswd -Identity $Identity -PassThru -Confirm:$false -WhatIf:$false -ErrorAction Stop
            Write-Verbose -Message 'Password reset successfully'
            if(-Not $NoChange)
            {
                Set-ADUser -ChangePasswordAtLogon $true -Identity $ADUser -Confirm:$false -WhatIf:$false -ErrorAction Stop
                Write-Verbose -Message 'Change password at logon set to True'
            }
            Unlock-ADAccount -Identity $ADUser -Confirm:$false -WhatIf:$false -ErrorAction Stop
            Write-Verbose -Message 'Useraccount unlocked'
            Get-SWPhonetic -Char $Password
        }
    }
    Catch
    {
        Throw $_
    }
}

function Get-SWADLastOriginatingChange 
{
    [CmdletBinding(ConfirmImpact='None')]
	Param (
		[Parameter(Mandatory=$true, 
				ValueFromPipeline=$true,
				HelpMessage='DN or ObjectGUID of the AD Object. Output from Get-ADObject can be pipelined to this function too.'
				)]
		[Object] $Identity,

        [Parameter(Mandatory=$true,
                HelpMessage='Name of attribute to determine LastOriginatingChange for'
                )]
        [String] $Attribute,

        [Parameter(Mandatory=$false,
                HelpMessage='Domaincontroller to query'
                )]
        [String] $Server
	)
    Begin
    {
        if($PSBoundParameters.ContainsKey('Server'))
        {
            $ServerParam = @{Server = $Server}
        }
        else
        {
            $ServerParam = @{}
        }
    }
	Process {
        $XML = New-Object -TypeName System.Xml.XmlDocument
        $ADObject = Get-ADObject -Identity $Identity -IncludeDeletedObjects -Property 'msDS-ReplAttributeMetaData' @ServerParam
        $xmlString = '<root>{0}</root>' -f [string]$ADObject.'msDS-ReplAttributeMetaData' -replace '[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD\u10000-u10FFFF]',' '
        $XML.LoadXml($xmlString)
        $AttributeOrigChange = $XML.SelectSingleNode("/root/DS_REPL_ATTR_META_DATA[pszAttributeName='$Attribute']/ftimeLastOriginatingChange").'#Text'
        if(-Not([string]::IsNullOrEmpty($AttributeOrigChange))) {
            Write-Output (Get-Date -Date $AttributeOrigChange).ToUniversalTime()
        }
		else
		{
			Write-Warning -Message "LastOriginatingChange not found for attribute $Attribute"
		}
	}
}

<#
.Synopsis
   Recursively restores an object and all it's child objects from Active Directory Recycle Bin
.DESCRIPTION
   Recursively restores either: 
    - Any deleted child from a certain object, e.i. any objects delted from within an OU.
    - A deleted item and all it's deleted child objects, i.e. a whole OU Structure.

    Things worth noting:
     - If an object is deleted and a new object is created with the same RDN and then also delted, 
       the script will always choose the oldest (first) deleted object.
     - To only restore objects deleted AFTER a certain time, use the parameter 
       TimeFilter.

    Supports both -WhatIf and -Confirm
   
.EXAMPLE
   Restore-ADTree.ps1 -Identity OU=Org,DC=lab,DC=lcl

   Will restore any objects deleted from the Organizational Unit Org and any of their child objects.
.EXAMPLE
   Restore-ADTree.ps1 -Identity OU=Org,DC=lab,DC=lcl -TimeFilter '2014-10-17 08:00'

   Will restore any objects deleted from the Organizational Unit Org and any of their child objects
   that were deleted after the time specified.
.EXAMPLE
   Restore-ADTree.ps1 -lastKnownRDN Org

   Will restore the object with lastknownRDN 'Org' and all its deleted child objects.
.LINK
   http://blog.simonw.se
.NOTES
   AUTHOR:       Jimmy Andersson, Knowledge Factory
   DATE:		 2014-03-20
   CHANGE DATE:  2015-01-22
   VERSION:      1.0 - First version by Jimmy Andersson, Knowledge Factory
                 2.0 - Rewrite by Simon Wåhlin, Knowledge Factory
                       Added PowerShell best practices
                       Now supports filter by datetime
                       Supports -WhatIf and -Confirm
                       Will handle conflicts by only restoring the first (oldest) deleted object
                       Added error handling
                 3.0 - Rewrite by Simon Wåhlin, Knowledge Factory
                       Based on feedback from Christoffer Andersson, Enfo Zipper.
                       Fixed issue with default time filter. Now using '16010101000000.0Z' converted to localtime.
                          Would result in errors converting '16010101000000.0Z' to UTC when in timezone east of UTC
                       Added support for checking the TimeFilter for 'IsDeleted' on the metadata,
                          If someone would update/change the object while it's in the DO container, whenChanged will be updated.
#>
Function Restore-SWADTree
{
    [Cmdletbinding(SupportsShouldProcess)]
                                                                                                                                                            Param (
    # Specifies LastKnownRDN of object to be restored.
	[Parameter(Mandatory,ParameterSetName='LastKnown')]
	[String]
	$lastKnownRDN,

    # Specifies DN of last known parent of object to restore.
	[Parameter(ParameterSetName='LastKnown')]
	[String]
	$lastKnownParent,

	# Specifies the identity of the object to be restored or its parent.
	[Parameter(Mandatory,ParameterSetName='Identity')]
	[String]
	$Identity,
	
	# Specifies which partition to restore from.
	# Defaults to default naming context.
	[Parameter(ParameterSetName='Identity')]
	[Parameter(ParameterSetName='LastKnown')]
	[String]
    $Partition = (Get-ADRootDSE).defaultNamingContext,

    # Only objects deleted afted this time will be restored.
    [Parameter(ParameterSetName='Identity')]
	[Parameter(ParameterSetName='LastKnown')]
	[DateTime]
	$TimeFilter = $(Get-Date 1601-01-01).ToLocalTime(),

	# Specifies whether to process live children or not.
    # This will search for deleted objects that used to reside
    # within objects that are not deleted.
    #
    # Use this to specify a root OU and recursively restore
    # any object deleted from within that OU
	[Parameter(ParameterSetName='Identity')]
	[Parameter(ParameterSetName='LastKnown')]
	[switch]
	$Includelivechildren,

	[Parameter(ParameterSetName='Identity')]
	[Parameter(ParameterSetName='LastKnown')]
	[switch]
	$PassThru
    )

    Begin
    {
        Import-Module ActiveDirectory -Verbose:$false



        $FilterDateTime = Get-Date $TimeFilter.ToUniversalTime() -f 'yyyyMMddHHmmss.0Z'

        function Restore-Tree
        <#
    .Synopsis
       Recursive function doing the actual restoring
    #>
        {
	        [CmdletBinding(SupportsShouldProcess)]
	        Param
	        (
		        [Parameter()]
		        [String]
		        $strObjectGUID,
		
		        [Parameter()]
		        [String]
		        $strNamingContext,

		        [Parameter()]
		        [String]
		        $strDelObjContainer,
		
		        [Parameter()]
		        [String]
		        $TimeFilter = '16010101000000.0Z',
	    
		        [Parameter()]
		        [Switch]
		        $IncludeLiveChildren,

	            [Parameter()]
	            [switch]
	            $PassThru
	        )
            Begin
            {
            
            }
            Process
            {
	            Try
                {
		            # Check if object exists already:
                    Write-Verbose -Message ''
                    Write-Verbose -Message "Processing object $strObjectGUID"
		            $objRestoredParent = Get-ADObject -Identity $strObjectGUID -Partition $strNamingContext -ErrorAction Stop

                    Write-Verbose -Message "Found object $($objRestoredParent.distinguishedName)"
		            Write-Verbose -Message "$($objRestoredParent.distinguishedName) is a live object and will not be restored."

		            if($IncludeLiveChildren)
		            {
                        Write-Verbose -Message "Searching for live child objects to $($objRestoredParent.distinguishedName)"
                        $Param = @{
                            SearchScope = 'Onelevel'
                            SearchBase = $objRestoredParent.distinguishedName
                            ldapFilter = '(objectClass=*)'
                            ResultPageSize = 300
                            ResultSetSize = $Null
                            ErrorAction = 'SilentlyContinue'
                        }
	                    $objChildren = Get-ADObject @Param

		                if ($objChildren -ne $null)
			            {
		    	            foreach ($objChild in $objChildren)
				            {
					            $Param = @{
						            strObjectGUID = $objChild.objectGUID
						            strNamingContext = $strNamingContext
                                    strDelObjContainer = $strDelObjContainer
						            IncludeLiveChildren = $IncludeLiveChildren
                                    TimeFilter = $TimeFilter
                                    PassThru = $PassThru
					            }
					            Restore-Tree @Param
				            }
			            }
                        else
                        {
                            Write-Verbose -Message 'No live child objects found'
                        }
		            }
	            }
	            Catch
	            {
		            # Object did not exist, let's try to restore it
                    Try
                    {
                        # Resolve ObjectGUID to distinguishedName for better verbose message
                        $Param = @{
                            Identity = $strObjectGUID
                            Partition = $strNamingContext
                            includeDeletedObjects = $true
                            Properties = 'msDS-LastKnownRDN','lastknownparent','whenChanged'
                            ErrorAction = 'Stop'
                        }
		                $objRestoredParent = Get-ADObject @Param
                        $DeletedTime = Get-SWADLastOriginatingChange -Identity $objRestoredParent.DistinguishedName -Attribute isDeleted
                        Write-Verbose -Message ('DeletedTime: {0} FilterTime: {1}' -f (Get-Date $DeletedTime -f 'yyyyMMddHHmmss.0Z'), $TimeFilter)
                        if((Get-Date $DeletedTime -f 'yyyyMMddHHmmss.0Z') -gt $TimeFilter)
                        {
                            Write-Verbose -Message "Restoring object $($objRestoredParent.distinguishedName)"
                            $ShouldProcessMsg = '{0} to {1} deleted at {2}' -f $objRestoredParent.'msDS-LastKnownRDN', $objRestoredParent.'lastknownparent', $objRestoredParent.'whenChanged'
                            Try
                            {
                                if($PSCmdlet.ShouldProcess($ShouldProcessMsg,'Restore'))
                                {
			                        Restore-ADobject -Identity $strObjectGUID -Partition $strNamingContext -Confirm:$false -ErrorAction Stop
                        
                                    $objRestoredParent = Get-ADObject -Identity $strObjectGUID -Partition $strNamingContext -ErrorAction Stop
			                        Write-Verbose -Message "Restored object: $($objRestoredParent.DistinguishedName)"
                                    if( $PassThru )
                                    {
                                        Write-Output $objRestoredParent
                                    }
                                }
                            }
                            Catch
                            {
                                $objRestoredParent = $Null
                                Write-Warning -Message "Failed to restore object $($objRestoredParent.distinguishedName)"
                                Write-Warning -Message $_.Exception.Message
                            }    
                        }
                        else {
                            Write-Verbose -Message ('Object {0} was filtered out by FilterTime' -f $objRestoredParent.DistinguishedName)
                        }
                    }
                    Catch
                    {
                        # No deleted object found.
                    }
	            }
	
                if($objRestoredParent)
                {
	                $strFilter = "(&(WhenChanged>=$TimeFilter)(lastknownParent=$($objRestoredParent.distinguishedName.Replace('\0','\\0'))))"
            
                    Write-Verbose -Message "Searching for deleted child objects of $($objRestoredParent.distinguishedName.Replace('\0','\\0'))"

                    $Param = @{
                        SearchScope = 'Subtree' 
                        SearchBase = $strDelObjContainer
                        includeDeletedObjects = $true
                        ldapFilter = $strFilter
                        ResultPageSize = 300
                        ResultSetSize = $null 
                        Properties = @('msDS-LastKnownRDN', 'WhenChanged')
                        ErrorAction = 'SilentlyContinue'
                    }
                
                    $AddMemberParams = @{
                        MemberType = 'NoteProperty'
                        Name = 'WhenDeleted'
                        PassThru = $true
                        Force = $true
                    }

                    # If multiple objects are conflicting, select only the oldest one
                    # to get newer objects, timeFilter will be used
                    $objChildren = Get-ADObject @Param |
                        Group-Object -Property msDS-LastKnownRDN |
                            foreach {
                                $_.Group | Foreach {
                                    Add-Member -InputObject $_ @AddMemberParams -Value (Get-SWADLastOriginatingChange -Identity $_.DistinguishedName -Attribute isDeleted)
                                } | Where-Object -FilterScript {(Get-Date $_.WhenDeleted -f 'yyyyMMddHHmmss.0Z') -gt $TimeFilter }
                                 Sort-Object -Property WhenDeleted |
                                            Select-Object -First 1
                            }

	                if ($objChildren)
	                {
                        Write-Verbose -Message 'Processing found child objects...'
    	                foreach ($objChild in $objChildren)
		                {
                            $Param = @{
                                strObjectGUID = $objChild.objectGUID
                                strNamingContext = $strNamingContext
                                strDelObjContainer = $strDelObjContainer
                                IncludeLiveChildren = $IncludeLiveChildren
                                TimeFilter = $TimeFilter
                                PassThru = $PassThru
                            }
			                Restore-Tree @Param
		                }
	                }
                    else
                    {
                        Write-Verbose -Message 'No deleted child objects found.'
                    }
                }
            }
        }
    }
    Process
    {
        $strDelObjContainer = (Get-ADDomain).DeletedObjectsContainer

        Switch ($PSCmdlet.ParameterSetName)
        {
            'Identity'
            {
                $Param = @{
                    Identity = $Identity
                    Partition = $Partition
                    includeDeletedObjects = $true
                    Properties = @('lastknownparent', 'whenChanged', 'isDeleted')
                }
                $objSearchResult = Get-ADObject @Param 
            }

            'LastKnown'
            {
                $FilterArray = @("(msds-lastknownRDN=$lastKnownRDN)","(WhenChanged>=$FilterDateTime)")

                if($PSBoundParameters.ContainsKey('lastknownParent'))
                {
                    $FilterArray += "(lastknownParent=$lastKnownParent)"
                }
            
                $strFilter = '(&{0})' -f ($FilterArray -join '')
                $Param = @{
                    SearchScope = 'SubTree'
                    SearchBase = $strDelObjContainer
                    includeDeletedObjects = $true
                    ldapFilter = $strFilter
                    Properties = @('lastknownparent', 'whenChanged', 'isDeleted', 'msDS-LastKnownRDN')
                }
	            $objSearchResult = Get-ADObject @Param | ForEach-Object {
                    if((Get-SWADLastOriginatingChange -Identity $_.distinguishedName -Attribute isDeleted) -gt $TimeFilter.ToUniversalTime()) {
                        $_
                    }
                }
            }
        }

        if ($objSearchResult)
        {
            if ($objSearchResult.Count -gt 1)
            {
                Write-Warning -Message 'Search returned more than one object, please refine search parameters.'
                Write-Warning -Message ''
                Write-Warning -Message ("`n{0}" -f ($objSearchResult | Format-Table msDS-LastKnownRDN, lastknownparent, whenChanged -AutoSize | Out-String))
                Write-Warning -Message ''
                Throw
            }
            else
            {
                $Param = @{
                    strObjectGUID = $objSearchResult.objectGUID
                    strNamingContext = $partition
                    IncludeLiveChildren = $includelivechildren
                    strDelObjContainer = $strDelObjContainer
                    TimeFilter = $FilterDateTime
                    PassThru = $PassThru
                }
                Restore-Tree @Param
            }
        }
        else
        {
            Write-Warning -Message 'No objects matching specified search terms.'
        }
    }
}

<#
    .SYNOPSIS
    Test a credential

    .DESCRIPTION
    Test a credential object or a username and password against a machine or domain.
    Can be used to validate service account passwords.

    .PARAMETER Credential
    Credential to test

    .PARAMETER UserName
    Username to test

    .PARAMETER Password
    Clear text password to test. 
    ATT!: Be aware that the password is written to screen and memory in clear text

    .PARAMETER ContextType
    Set where to validate the credential.
    Can be Domain, Machine or ApplicationDirectory

    .PARAMETER Server
    Set remote computer or domain to validate against.

    .EXAMPLE
    Test-SWADCredential -UserName svc-my-service -Password Kgse(70g!S.
    True

    .EXAMPLE
    Test-SWADCredential -Credential $Cred
    True
#>
function Test-SWADCredential 
{
    [CmdletBinding(DefaultParameterSetName='Credential')]
    Param
    (
        [Parameter(Mandatory=$true,ParameterSetName='Credential')]
        [pscredential]
        $Credential,
        
        [Parameter(Mandatory=$true,ParameterSetName='Cleartext')]
        [ValidateNotNullOrEmpty()]
        [string]$UserName,
        
        [Parameter(Mandatory=$true,ParameterSetName='Cleartext')]
        [string]$Password,

        [Parameter(Mandatory=$false,ParameterSetName='Cleartext')]
        [Parameter(Mandatory=$false,ParameterSetName='Credential')]
        [ValidateSet('ApplicationDirectory','Domain','Machine')]
        [string]$ContextType = 'Domain',

        [Parameter(Mandatory=$false,ParameterSetName='Cleartext')]
        [Parameter(Mandatory=$false,ParameterSetName='Credential')]
        [String]$Server
    )
    
    try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
        if($PSCmdlet.ParameterSetName -eq 'ClearText') {
            $EncPassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
            $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserName,$EncPassword
        }
        try {
            if($PSBoundParameters.ContainsKey('Server'))
            {
                $PrincipalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($ContextType,$Server)
            }
            else
            {
                $PrincipalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($ContextType)
            }
        }
        catch {
            Write-Error -Message "Failed to connect to server using contect: $ContextType"
        }
        try
        {
            $PrincipalContext.ValidateCredentials($Credential.UserName, $Credential.GetNetworkCredential().Password,'Negotiate')
        }
        catch [UnauthorizedAccessException]
        {
            Write-Warning -Message "Access denied when connecting to server."
            return $false
        }
        catch
        {
            Write-Error -Exception $_.Exception -Message "Unhandled error occured"
        }
    }
    catch {
        throw
    }
}

function Get-SWADGroupMember
{
    [cmdletbinding(
        DefaultParameterSetName = 'Default'
    )]
    param(
        [Parameter(
            Mandatory         = $true,
            Position          = 0,
            ValueFromPipeline = $true,
            ParameterSetName  = 'Default'
        )]
        [Parameter(
            Mandatory         = $true,
            Position          = 0,
            ValueFromPipeline = $true,
            ParameterSetName  = 'Nested'
        )]
        [string]
        $Identity,
		
        [Parameter(
            ParameterSetName  = 'Nested'
        )]
		[Parameter(
            ParameterSetName  = 'Default'
        )]
		[String]
		$Server,
        
        [Parameter(
            ParameterSetName  = 'Nested'
        )]
        $TypeDictionary  = @{'user'='if($_.Enabled){"+"}else{"-"}';'group'='"#"';'contact'='"¤"'},

        [Parameter(
            Mandatory         = $true,
            ParameterSetName  = 'Nested'
        )]
		[Switch]
		$NestOutput
    )
	Begin
	{
		$GroupParams = @{
			Properties  = 'members','objectClass'
            ErrorAction = 'Stop'
		}
		$ServerParam = @{}
        if($PSBoundParameters.ContainsKey('Server'))
        {
            $ServerParam.Server = $Server
        }
        $Domain = Get-ADDomain @ServerParam
	}
    Process
    {
        Try
        {
            $Group = Get-ADGroup -Identity $Identity @GroupParams @ServerParam
            $ParentInvocation = Get-Variable -Name MyInvocation -Scope 1 -ValueOnly
            if($ParentInvocation.MyCommand.Name -ne $MyInvocation.MyCommand.Name)
            {
                Write-Verbose -Message 'Not recursive call, set start variables.'
                $IsRecursice = $false
                $Script:GroupMemberStart = $Group.distinguishedName
            }
            else
            {
                Write-Verbose -Message 'Recursive call, check for nested loop.'
                $IsRecursive = $true
                if($Script:GroupMemberStart -like $Group.distinguishedName)
                {
                    $PreviousGroup = Get-Variable -Name Group -Scope 1 -ValueOnly
                    Write-Warning -Message ('Nested loop detected in: {0}' -f $Group.distinguishedName)
                    Write-Warning -Message ('Parent group: {0}' -f $PreviousGroup.distinguishedName)
                    Throw ('Nested group loop detected in group: {0}' -f $Group.distinguishedName)
                }
            }
            Write-Verbose -Message 'No loop detected, write output.'
            
            # Determine RID (for use later on when finding members by "Primary Group"
            $RID = $($Group.SID.toString()).replace(('{0}-' -f $Domain.DomainSID.toString()),'')

            # Lookup all direct members, cant use Get-ADGroupMember since that doesnt return contact objects
            Write-Verbose -Message 'Looking direct up members...'
            $i = 0
            $Members = @(foreach ($Member in $Group.Members) {
                Get-ADObject @ServerParam -Identity $Member -Properties UserAccountControl, sAMAccountName | 
                    Select-Object -Property Name, DistinguishedName, sAMAccountName, @{n='Enabled';e={-not[bool]($_.userAccountControl[0] -band 2)}}, objectClass
            })

            # Finding members based on "Primary Group"
            Write-Verbose -Message 'Looking up members by PrimaryGroup...'
            $PrimaryGroupMembers = @(Get-ADObject @ServerParam -LDAPFilter "(&(objectClass=user)(PrimaryGroupID=$RID))" -Properties UserAccountControl, sAMAccountName | 
                    Select-Object -Property Name, DistinguishedName, sAMAccountName, @{n='Enabled';e={-not[bool]($_.userAccountControl[0] -band 2)}}, objectClass)
            
            [System.Void]$PSBoundParameters.Remove('Identity')

            foreach($Member in ($PrimaryGroupMembers + $Members))
            {
                $Result = $Member
                
                if($Result.objectClass -eq 'group')
                {
                    if($PSCmdlet.ParameterSetName -eq 'Nested')
                    {
                        Add-Member -InputObject $Result -MemberType NoteProperty -Name Members -Value ($Result.DistinguishedName | Get-SWADGroupMember @PSBoundParameters) -Force
                        Write-Output -InputObject $Result
                    }
                    else
                    {
                        Write-Output -InputObject $Result
                        $Result.distinguishedName | Get-SWADGroupMember @PSBoundParameters
                    }
                }
                else
                {
                    Write-Output -InputObject $Result
                }
            }
        }
        Catch
        {
            Throw   
        }
    }
}

function Get-SWADGroupMemberReport
{
    [cmdletbinding()]
    param(
        [Parameter(
            Mandatory         = $true,
            Position          = 0,
            ValueFromPipeline = $true
        )]
        [string]
        $Identity,

        [Parameter()]
        [ValidateSet('Name','distinguishedName','sAMAccountName')]
        [string]
        $Property = 'Name',
        
        [Parameter()]
        $TypeDictionary  = @{
            'user'      = 'if($_.Enabled){" + "}else{" - "}'
            'group'     = '" # "'
            'contact'   = '" § "'
            'computer'  = 'if($_.Enabled){" ¤ "}else{" = "}'
        },
		
		[Parameter()]
		[String]
		$Server
    )
	Begin
	{
		$GroupParams = @{
			Properties  = 'members','objectClass'
            ErrorAction = 'Stop'
		}
		$ServerParam = @{}
        if($PSBoundParameters.ContainsKey('Server'))
        {
            $ServerParam.Server = $Server
        }
        $Domain = Get-ADDomain @ServerParam
	}
    Process
    {
        Try
        {
            $Result = Get-ADGroup -Identity $Identity @GroupParams @ServerParam | Select-Object Name, DistinguishedName, sAMAccountName, objectClass, @{
                name       = 'members'
                expression = {Get-SWADGroupMember -Identity $_ -NestOutput}
            } 
            
            $Result | ConvertTo-StringTree -NameProperty $Property -ChildProperty 'Members' -TypeDictionary $TypeDictionary -TypeProperty objectClass
        }
        Catch
        {
            Throw   
        }
    }
}

Export-ModuleMember -Function '*-SW*'
