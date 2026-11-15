# The PowerShell tables VibePath reads at build time (SPEC section 10): every alias, function and
# cmdlet a fresh `-NoProfile` session of PowerShell 7 and of Windows PowerShell 5.1 resolves by
# name, from PowerShell itself and the modules Windows ships (under $PSHOME and System32's
# WindowsPowerShell\v1.0\Modules). Modules a user or a program installed elsewhere are left out:
# they differ from PC to PC. Written to assets\ps7.txt and assets\ps51.txt as
# `name<TAB>kind<TAB>target` (an alias's command, a command's module), sorted by name.
# Run it again after a PowerShell update: .\tools\ps-builtins.ps1
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\.."
$query = @'
$sys = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules'
$own = @($PSHOME, $sys) | ForEach-Object { $_.TrimEnd('\') + '\' }
$builtin = {
    param($c)
    $m = $c.Module
    if (-not $m) { return $true }
    $base = [string]$m.ModuleBase
    if (-not $base) { return $true }
    foreach ($o in $own) { if ($base.StartsWith($o, [StringComparison]::OrdinalIgnoreCase) -or ($base + '\') -ieq $o) { return $true } }
    return $false
}
$lines = foreach ($c in Get-Command -CommandType Alias, Function, Cmdlet -ErrorAction SilentlyContinue) {
    if (-not (& $builtin $c)) { continue }
    $target = switch ($c.CommandType) {
        'Alias' { [string]$c.Definition }
        default { [string]$c.Source }
    }
    "{0}`t{1}`t{2}" -f $c.Name, $c.CommandType, $target
}
$lines | Sort-Object -Unique -CaseSensitive | ForEach-Object { [Console]::Out.WriteLine($_) }
'@
$pairs = @(
    @{ exe = (Get-Command pwsh -CommandType Application | Where-Object { $_.Source -notmatch 'WindowsApps' } | Select-Object -First 1).Source; out = "$root\assets\ps7.txt" },
    @{ exe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"; out = "$root\assets\ps51.txt" }
)
foreach ($p in $pairs) {
    if (-not $p.exe) { throw "PowerShell 7 (pwsh.exe) was not found" }
    $text = & $p.exe -NoProfile -NonInteractive -Command $query
    if ($LASTEXITCODE -ne 0 -or -not $text) { throw "$($p.exe) gave no table" }
    [IO.File]::WriteAllText($p.out, (($text | Where-Object { $_ -ne '' }) -join "`n") + "`n", (New-Object Text.UTF8Encoding $false))
    "{0}: {1} commands from {2}" -f $p.out, @($text).Count, $p.exe
}
