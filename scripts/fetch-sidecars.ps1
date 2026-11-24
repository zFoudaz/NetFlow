$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$RepoRoot = Split-Path -Parent $PSScriptRoot
$BinDir = Join-Path $RepoRoot "src-tauri\binaries"
$ResDir = Join-Path $RepoRoot "src-tauri\resources"

New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
New-Item -ItemType Directory -Force -Path $ResDir | Out-Null

$Sidecars = @(
    @{
        Name        = "sing-box 1.14.4"
        Url         = "https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-windows-amd64.zip"
        ZipName     = "sing-box-1.14.4-windows-amd64.zip"
        InnerPath   = "sing-box-1.14.4-windows-amd64\sing-box.exe"
        TargetPath  = Join-Path $BinDir "sing-box-x86_64-pc-windows-msvc.exe"
    },
    @{
        Name        = "wintun 0.14.1"
        Url         = "https://www.wintun.net/builds/wintun-0.14.1.zip"
        ZipName     = "wintun-0.14.1.zip"
        InnerPath   = "wintun\bin\amd64\wintun.dll"
        TargetPath  = Join-Path $ResDir "wintun.dll"
    }
)

$TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("netflow-sidecars-" + [Guid]::NewGuid().ToString("N"))

try {
    foreach ($item in $Sidecars) {
        if (Test-Path $item.TargetPath) {
            Write-Host "[skip] $($item.Name) already present at $($item.TargetPath)"
            continue
        }

        if (-not (Test-Path $TempRoot)) {
            New-Item -ItemType Directory -Force -Path $TempRoot | Out-Null
        }

        $zipPath = Join-Path $TempRoot $item.ZipName
        $extractDir = Join-Path $TempRoot ([System.IO.Path]::GetFileNameWithoutExtension($item.ZipName))

        Write-Host "[fetch] Downloading $($item.Name) from $($item.Url)..."
        Invoke-WebRequest -Uri $item.Url -OutFile $zipPath -UseBasicParsing

        Write-Host "[extract] Extracting $($item.InnerPath)..."
        Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

        $sourceFile = Join-Path $extractDir $item.InnerPath
        if (-not (Test-Path $sourceFile)) {
            throw "Expected file '$($item.InnerPath)' not found inside '$($item.ZipName)'."
        }

        Copy-Item -Path $sourceFile -Destination $item.TargetPath -Force
        Write-Host "[ok] Installed $($item.Name) -> $($item.TargetPath)"
    }
}
finally {
    if (Test-Path $TempRoot) {
        Remove-Item -Recurse -Force $TempRoot -ErrorAction SilentlyContinue
    }
}
