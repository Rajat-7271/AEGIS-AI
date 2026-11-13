# Read-only NTFS ACL audit for an existing continuity-state file.
# Never modifies the file or its access control list.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$StatePath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$item = Get-Item -LiteralPath $StatePath -Force -ErrorAction Stop
if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Continuity state must be a regular non-reparse-point file.'
}
$acl = Get-Acl -LiteralPath $item.FullName
$allowed = @(
    [Security.Principal.WindowsIdentity]::GetCurrent().User.Value,
    'S-1-5-18', # SYSTEM
    'S-1-5-32-544' # Administrators
)
$unsafe = @()
foreach ($rule in $acl.Access) {
    if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
    $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    $rights = $rule.FileSystemRights
    $canWrite = ($rights -band [Security.AccessControl.FileSystemRights]::Write) -ne 0 -or
        ($rights -band [Security.AccessControl.FileSystemRights]::Modify) -ne 0 -or
        ($rights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne 0
    if ($canWrite -and $sid -notin $allowed) {
        $unsafe += $sid
    }
}
[pscustomobject]@{
    Path = $item.FullName
    Owner = $acl.Owner
    InheritanceEnabled = -not $acl.AreAccessRulesProtected
    UnexpectedWritableSids = @($unsafe | Select-Object -Unique)
    Pass = ($unsafe.Count -eq 0)
} | ConvertTo-Json -Compress
if ($unsafe.Count -gt 0) { throw 'Unsafe continuity-state write permissions detected.' }
