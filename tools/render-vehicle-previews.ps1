# Renders one preview per entry of a body map produced by the vehicle body scan.
# The example binary writes <name>-primary.webp and <name>-thumb.webp.
param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [Parameter(Mandatory = $true)][string]$BodyMap,
    [Parameter(Mandatory = $true)][string]$Textures,
    [Parameter(Mandatory = $true)][string]$Out,
    [string]$VehicleData,
    [string]$Colors,
    [string]$WheelKits,
    [int]$Jobs = 4,
    [int]$Size = 1024,
    [int]$Thumb = 320,
    [string]$Log = "render.log"
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $Out | Out-Null
$map = Get-Content $BodyMap -Raw | ConvertFrom-Json
$queue = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
foreach ($entry in $map) { $queue.Enqueue($entry) }
$failed = [System.Collections.Concurrent.ConcurrentBag[string]]::new()
$done = 0
$total = $queue.Count

$shared = @("--textures", $Textures, "--out", $Out, "--size", "$Size", "--thumb", "$Thumb")
if ($VehicleData) { $shared += @("--vehicle-data", $VehicleData) }
if ($Colors) { $shared += @("--colors", $Colors) }
if ($WheelKits) { $shared += @("--wheel-kits", $WheelKits) }

$workers = 1..$Jobs | ForEach-Object {
    Start-ThreadJob -ArgumentList $Exe, $queue, $failed, $shared, $Log -ScriptBlock {
        param($exe, $queue, $failed, $shared, $log)
        $entry = $null
        while ($queue.TryDequeue([ref]$entry)) {
            $name = $entry.model.ToLowerInvariant()
            $primary = Join-Path $shared[($shared.IndexOf("--out") + 1)] "$name-primary.webp"
            if (Test-Path $primary) { continue }
            $args = @($entry.file) + $shared + @("--model", $entry.model, "--name", $name)
            $output = & $exe @args 2>&1
            if ($LASTEXITCODE -ne 0) {
                $failed.Add($name)
                Add-Content $log "$name`: $($output | Select-Object -Last 1)"
            }
        }
    }
}

while ($done -lt $total) {
    $remaining = $queue.Count
    $rendered = ($total - $remaining - $failed.Count)
    Write-Host "$rendered/$total rendered, $($failed.Count) failed, $remaining queued"
    if ($remaining -eq 0) { break }
    Start-Sleep -Seconds 5
}
$workers | Wait-Job | Remove-Job
Write-Host "done: $($failed.Count) failed"
$failed | ForEach-Object { Write-Host "failed: $_" }
