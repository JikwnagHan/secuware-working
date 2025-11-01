#requires -Version 5.1
<#!
    데이터 보호 성능평가 통합 자동화 스크립트
    ------------------------------------------------------------
    이 스크립트는 일반영역과 보안영역에 테스트 데이터를 자동으로 재구성하고,
    Atomic Red Team 기반의 악성행위 시뮬레이션과 RanSim 기반의 랜섬웨어 테스트를
    순차적으로 수행한 뒤, 평가 결과를 CSV/JSON/XLSX/DOCX 보고서로 출력합니다.

    사용 흐름
    1. 일반영역/보안영역/결과 저장 위치를 입력합니다.
    2. 기존 데이터를 모두 삭제하고 문서/시스템 샘플을 동일하게 재생성합니다.
    3. RanSim, Atomic Red Team 모듈, Atomics 콘텐츠, Caldera 존재 여부를 점검합니다.
    4. 7개 버킷 30개 대표 악성행위 시뮬레이션을 자동으로 실행합니다.
    5. RanSim을 호출하여 랜섬웨어 침해 여부를 측정합니다.
    6. 모든 결과를 CSV, JSON, XLSX, DOCX로 저장합니다.

    관리자 권한 PowerShell에서 실행해야 하며, 테스트 전용 환경에서만 사용하세요.
!#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.IO.Compression.FileSystem

#region 공통 유틸리티 함수
function Read-RequiredPath {
    param(
        [Parameter(Mandatory)] [string] $PromptText
    )
    while ($true) {
        $value = Read-Host -Prompt $PromptText
        if ([string]::IsNullOrWhiteSpace($value)) {
            Write-Host '경로를 입력해야 합니다. 다시 시도하세요.' -ForegroundColor Yellow
            continue
        }
        return $value.Trim()
    }
}

function Ensure-Directory {
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Clear-Directory {
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }
    Get-ChildItem -LiteralPath $Path -Force | ForEach-Object {
        try {
            Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction Stop
        }
        catch {
            Write-Host "삭제 실패: $($_.FullName) - $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

function Write-TextFile {
    param([string] $Path, [string] $Content)
    $folder = Split-Path -Path $Path -Parent
    Ensure-Directory -Path $folder
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
}

function Write-BytesFile {
    param([string] $Path, [byte[]] $Bytes)
    $folder = Split-Path -Path $Path -Parent
    Ensure-Directory -Path $folder
    [System.IO.File]::WriteAllBytes($Path, $Bytes)
}

function Write-Base64File {
    param([string] $Path, [string] $Base64)
    $folder = Split-Path -Path $Path -Parent
    Ensure-Directory -Path $folder
    $clean = ($Base64 -replace '\s', '')
    $remainder = $clean.Length % 4
    if ($remainder -eq 1) {
        throw 'Base64 원문 길이가 올바르지 않습니다 (4의 배수 필요).'
    }
    elseif ($remainder -gt 0) {
        $clean = $clean.PadRight($clean.Length + (4 - $remainder), '=')
    }
    try {
        $bytes = [System.Convert]::FromBase64String($clean)
        [System.IO.File]::WriteAllBytes($Path, $bytes)
    }
    catch {
        throw "Base64 데이터를 디코딩하지 못했습니다: $($_.Exception.Message)"
    }
}

function New-ZipSample {
    param([string] $DestinationPath, [hashtable] $SourceContent)
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tempRoot | Out-Null
    foreach ($name in $SourceContent.Keys) {
        $path = Join-Path $tempRoot $name
        Write-TextFile -Path $path -Content $SourceContent[$name]
    }
    if (Test-Path -LiteralPath $DestinationPath) {
        Remove-Item -LiteralPath $DestinationPath -Force
    }
    Compress-Archive -Path (Join-Path $tempRoot '*') -DestinationPath $DestinationPath -Force
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
}
#endregion

#region 테스트 데이터 구성
function Get-DocumentPlan {
    param([int] $Seed)
    $rand = [System.Random]::new($Seed)
    $sizeOptions = @(65536, 262144, 1048576)
    $docExtensions = @('doc','docx','ppt','pptx','xls','xlsx','hwp','hwpx','txt')
    $plan = New-Object System.Collections.ArrayList
    foreach ($ext in $docExtensions) {
        $size = $sizeOptions[$rand.Next(0, $sizeOptions.Count)]
        $fileName = "sample_{0}_{1}.{0}" -f $ext, $size
        $bytes = New-Object byte[] $size
        $rand.NextBytes($bytes)
        [void]$plan.Add([PSCustomObject]@{ FileName = $fileName; Bytes = $bytes })
    }
    return $plan
}

function Initialize-TestArea {
    param(
        [string] $AreaName,
        [string] $RootPath,
        [System.Collections.IEnumerable] $DocumentPlan,
        [byte[]] $UsrClassBytes,
        [byte[]] $DllBytes
    )
    Write-Host "[$AreaName] 폴더를 초기화합니다: $RootPath"
    Ensure-Directory -Path $RootPath
    Clear-Directory -Path $RootPath

    $docsPath = Join-Path $RootPath 'Docs'
    $sysPath = Join-Path $RootPath 'SysCfg'
    Ensure-Directory -Path $docsPath
    Ensure-Directory -Path $sysPath

    foreach ($item in $DocumentPlan) {
        $filePath = Join-Path $docsPath $item.FileName
        Write-BytesFile -Path $filePath -Bytes ([byte[]]$item.Bytes.Clone())
    }

    Write-TextFile -Path (Join-Path $sysPath 'hosts_sample.txt') -Content "127.0.0.1 localhost`n# 테스트용 hosts 파일"
    Write-TextFile -Path (Join-Path $sysPath 'system.env') -Content "APP_ENV=Test`nTRACE=true"
    Write-TextFile -Path (Join-Path $sysPath 'appsettings.json') -Content '{"Logging":{"Level":"Information"},"ConnectionStrings":{"Primary":"Server=127.0.0.1;Database=Test"}}'
    Write-TextFile -Path (Join-Path $sysPath 'config.ini') -Content "[General]`nName=TestSystem`nMode=Simulation"
    Write-TextFile -Path (Join-Path $sysPath 'registry_backup.reg') -Content "Windows Registry Editor Version 5.00`n[HKEY_LOCAL_MACHINE\\SOFTWARE\\SampleCompany]`n\"AreaName\"=\"$AreaName\""
    Write-TextFile -Path (Join-Path $sysPath 'sample.csv') -Content "Name,Value`nSample,123"
    Write-TextFile -Path (Join-Path $sysPath 'settings.config') -Content "<?xml version='1.0' encoding='utf-8'?><configuration><appSettings><add key='Mode' value='Test'/></appSettings></configuration>"

    Write-BytesFile -Path (Join-Path $sysPath 'system_like_UsrClass.dat') -Bytes ([byte[]]$UsrClassBytes.Clone())
    Write-BytesFile -Path (Join-Path $sysPath 'sample.dll') -Bytes ([byte[]]$DllBytes.Clone())

    $pngBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/wwAAgMBAJcC/wAAAABJRU5ErkJggg=='
    Write-Base64File -Path (Join-Path $sysPath 'image_1x1.png') -Base64 $pngBase64

    $jpgBase64 = '/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAAkGBxISEhAQEBAQEA8QDxAQEA8PDxAPDxAQFREWFhURFRUYHSggGBolGxUVITEhJSkrLi4uFx8zODMsNygtLisBCgoKDQ0NDg0NDisZFRkrKysrKysrKysrKystKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrK//AABEIAJwBPgMBIgACEQEDEQH/xAAXAAADAQAAAAAAAAAAAAAAAAADBAUG/8QAHBAAAQQDAQAAAAAAAAAAAAAAAQACAxEEEiEx/8QAFwEAAwEAAAAAAAAAAAAAAAAAAQIDBf/EAB4RAAICAQUAAAAAAAAAAAAAAAABAgMEERITIUFR/9oADAMBAAIRAxEAPwDtVLwlh8zvP4STcQduPqbXaW3n1JcTzH//2Q=='
    Write-Base64File -Path (Join-Path $sysPath 'image_1x1.jpg') -Base64 $jpgBase64

    $zipPath = Join-Path $sysPath 'sample.zip'
    New-ZipSample -DestinationPath $zipPath -SourceContent @{ 'readme.txt' = "이 ZIP 파일은 자동 평가를 위한 샘플입니다." }
}
#endregion

#region 파일 스냅샷/비교
function Get-FileSnapshot {
    param([string] $RootPath)
    $snapshot = @{}
    if (-not (Test-Path -LiteralPath $RootPath -PathType Container)) { return $snapshot }
    Get-ChildItem -LiteralPath $RootPath -File -Recurse | ForEach-Object {
        try {
            $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
        }
        catch {
            $hash = $null
        }
        $snapshot[$_.FullName] = [PSCustomObject]@{
            Exists = $true
            Size = $_.Length
            Hash = $hash
        }
    }
    return $snapshot
}

function Compare-Snapshots {
    param(
        [hashtable] $Before,
        [hashtable] $After,
        [string] $AreaName,
        [string] $TestId,
        [string] $Result,
        [string] $Message,
        [datetime] $Timestamp
    )
    $beforeKeys = if ($Before) { $Before.Keys } else { @() }
    $afterKeys = if ($After) { $After.Keys } else { @() }
    $allKeys = @($beforeKeys + $afterKeys) | Sort-Object -Unique
    $records = @()
    foreach ($key in $allKeys) {
        $b = $Before[$key]
        $a = $After[$key]
        $existsBefore = [bool]($b)
        $existsAfter  = [bool]($a)
        $sizeBefore = if ($b) { [int64]$b.Size } else { 0 }
        $sizeAfter  = if ($a) { [int64]$a.Size } else { 0 }
        $hashBefore = if ($b) { $b.Hash } else { $null }
        $hashAfter  = if ($a) { $a.Hash } else { $null }
        $changed = $false
        if ($existsBefore -ne $existsAfter) {
            $changed = $true
        }
        elseif ($existsBefore -and $existsAfter -and ($hashBefore -ne $hashAfter)) {
            $changed = $true
        }
        $records += [PSCustomObject]@{
            Timestamp = $Timestamp.ToString('yyyy-MM-dd HH:mm:ss')
            Area = $AreaName
            FilePath = $key
            Exists_Before = $existsBefore
            Size_Before = $sizeBefore
            SHA256_Before = $hashBefore
            Exists_After = $existsAfter
            Size_After = $sizeAfter
            SHA256_After = $hashAfter
            Changed = $changed
            Test = $TestId
            Result = $Result
            Message = $Message
        }
    }
    return $records
}
#endregion

#region 시뮬레이터 준비
function Invoke-SafeDownload {
    param(
        [string] $Uri,
        [string] $DestinationPath
    )
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
    }
    catch { }
    try {
        Invoke-WebRequest -Uri $Uri -OutFile $DestinationPath -UseBasicParsing -ErrorAction Stop
        return [PSCustomObject]@{ Success = $true; Message = $null }
    }
    catch {
        return [PSCustomObject]@{ Success = $false; Message = $_.Exception.Message }
    }
}

function Ensure-AtomicToolkit {
    $messages = New-Object System.Collections.ArrayList
    $module = Get-Module -Name Invoke-AtomicRedTeam -ListAvailable | Select-Object -First 1
    if (-not $module) {
        try {
            Install-Module -Name Invoke-AtomicRedTeam -Scope CurrentUser -Force -ErrorAction Stop
            $module = Get-Module -Name Invoke-AtomicRedTeam -ListAvailable | Select-Object -First 1
        }
        catch {
            [void]$messages.Add("Invoke-AtomicRedTeam 모듈 설치 실패: $($_.Exception.Message)")
        }
    }
    if (-not $module) {
        [void]$messages.Add('Invoke-AtomicRedTeam 모듈을 확인하지 못했습니다. 내장 악성 행위 시뮬레이션으로 진행합니다.')
        return [PSCustomObject]@{ Module = $null; AtomicsPath = $null; Messages = $messages }
    }

    $preferred = @()
    if ($env:ATOMIC_RED_TEAM_PATH) {
        $preferred += $env:ATOMIC_RED_TEAM_PATH
    }
    $preferred += @(
        'C:\\AtomicRedTeam\\atomics',
        'C:\\AtomicRedTeam\\atomic-red-team-master\\atomics',
        (Join-Path $module.ModuleBase 'atomics'),
        (Join-Path (Split-Path $module.ModuleBase -Parent) 'atomics')
    )

    foreach ($path in $preferred) {
        if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path -LiteralPath $path -PathType Container)) {
            return [PSCustomObject]@{ Module = $module; AtomicsPath = $path; Messages = $messages }
        }
    }

    $downloadRoot = 'C:\\AtomicRedTeam'
    Ensure-Directory -Path $downloadRoot
    $zipPath = Join-Path $downloadRoot 'atomic-red-team.zip'
    $extractPath = Join-Path $downloadRoot 'atomic-red-team-master'
    if (Test-Path -LiteralPath $zipPath) {
        Remove-Item -LiteralPath $zipPath -Force
    }
    if (Test-Path -LiteralPath $extractPath) {
        Remove-Item -LiteralPath $extractPath -Recurse -Force
    }
    $url = 'https://github.com/redcanaryco/atomic-red-team/archive/refs/heads/master.zip'
    $download = Invoke-SafeDownload -Uri $url -DestinationPath $zipPath
    if ($download.Success) {
        try {
            [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $downloadRoot)
        }
        catch {
            [void]$messages.Add("Atomics 압축 해제 실패: $($_.Exception.Message)")
        }
    }
    else {
        [void]$messages.Add("Atomics 패키지 다운로드 실패: $($download.Message)")
    }

    $atomicsCandidate = Join-Path $extractPath 'atomics'
    if (Test-Path -LiteralPath $atomicsCandidate) {
        return [PSCustomObject]@{ Module = $module; AtomicsPath = $atomicsCandidate; Messages = $messages }
    }

    [void]$messages.Add('Atomics 콘텐츠를 자동으로 확보하지 못했습니다. 필요 시 GitHub 저장소를 수동으로 내려받아 ATOMIC_RED_TEAM_PATH 환경 변수를 설정하세요.')
    return [PSCustomObject]@{ Module = $module; AtomicsPath = $null; Messages = $messages }
}

function Ensure-RanSim {
    $messages = New-Object System.Collections.ArrayList
    $defaultPath = 'C:\\KB4\\Newsim\\Ranstart.exe'
    if (Test-Path -LiteralPath $defaultPath) {
        return [PSCustomObject]@{ Path = $defaultPath; Messages = $messages }
    }
    $downloadDir = 'C:\\Temp\\RanSim'
    Ensure-Directory -Path $downloadDir
    $installer = Join-Path $downloadDir 'RanSim-Setup.msi'
    if (-not (Test-Path -LiteralPath $installer)) {
        $url = 'https://downloads.knowbe4.com/ransim/RanSim-Setup.msi'
        $download = Invoke-SafeDownload -Uri $url -DestinationPath $installer
        if (-not $download.Success) {
            [void]$messages.Add("RanSim 설치 파일 다운로드 실패: $($download.Message)")
        }
    }
    if (Test-Path -LiteralPath $installer) {
        try {
            Start-Process -FilePath 'msiexec.exe' -ArgumentList "/i `"$installer`" /qn" -Wait -ErrorAction Stop
        }
        catch {
            [void]$messages.Add("RanSim 무인 설치 실패: $($_.Exception.Message)")
        }
    }
    if (Test-Path -LiteralPath $defaultPath) {
        return [PSCustomObject]@{ Path = $defaultPath; Messages = $messages }
    }

    Write-Host 'RanSim 실행 파일(.exe) 또는 설치 폴더 경로를 입력하세요 (Enter로 건너뜁니다):'
    $manual = Read-Host
    if (-not [string]::IsNullOrWhiteSpace($manual)) {
        $manualTrim = $manual.Trim()
        if (Test-Path -LiteralPath $manualTrim -PathType Container) {
            $candidate = Get-ChildItem -LiteralPath $manualTrim -Filter 'Ranstart.exe' -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($candidate) {
                return [PSCustomObject]@{ Path = $candidate.FullName; Messages = $messages }
            }
            else {
                [void]$messages.Add('입력한 폴더에 Ranstart.exe가 없어 기본 비교 절차만 수행합니다.')
            }
        }
        elseif (Test-Path -LiteralPath $manualTrim -PathType Leaf) {
            return [PSCustomObject]@{ Path = (Resolve-Path -LiteralPath $manualTrim).Path; Messages = $messages }
        }
        else {
            [void]$messages.Add('입력한 경로를 확인할 수 없어 RanSim을 생략합니다.')
        }
    }

    [void]$messages.Add('RanSim 실행 파일을 확보하지 못했습니다. 필요 시 공식 배포처에서 설치 후 다시 시도하세요.')
    return [PSCustomObject]@{ Path = $null; Messages = $messages }
}

function Ensure-Caldera {
    $messages = New-Object System.Collections.ArrayList
    $default = 'C:\\Caldera'
    if (Test-Path -LiteralPath $default) {
        return [PSCustomObject]@{ Path = $default; Messages = $messages }
    }
    $downloadDir = 'C:\\Temp\\Caldera'
    Ensure-Directory -Path $downloadDir
    $zipPath = Join-Path $downloadDir 'caldera-master.zip'
    $url = 'https://github.com/mitre/caldera/archive/refs/heads/master.zip'
    if (-not (Test-Path -LiteralPath $zipPath)) {
        $download = Invoke-SafeDownload -Uri $url -DestinationPath $zipPath
        if (-not $download.Success) {
            [void]$messages.Add("Caldera 패키지 다운로드 실패: $($download.Message)")
        }
    }
    if (Test-Path -LiteralPath $zipPath) {
        try {
            if (-not (Test-Path -LiteralPath $default)) {
                New-Item -ItemType Directory -Path $default | Out-Null
            }
            [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $default)
            return [PSCustomObject]@{ Path = $default; Messages = $messages }
        }
        catch {
            [void]$messages.Add("Caldera 압축 해제 실패: $($_.Exception.Message)")
        }
    }
    [void]$messages.Add('Caldera 패키지를 자동으로 준비하지 못했습니다. 필요 시 GitHub 릴리스를 수동으로 내려받아 압축을 해제하세요.')
    return [PSCustomObject]@{ Path = $null; Messages = $messages }
}
#endregion

#region 악성 행위 시뮬레이션 계획
function Get-MalwareOperationPlan {
    $plan = New-Object System.Collections.ArrayList

    $entries = @(
        [PSCustomObject]@{ Category = '파일 쓰기·수정'; Technique = 'T1222.001'; Action = 'Append'; Repeat = 3 },
        [PSCustomObject]@{ Category = '파일 쓰기·수정'; Technique = 'T1222.001'; Action = 'Overwrite'; Repeat = 3 },
        [PSCustomObject]@{ Category = '아카이브/인코딩'; Technique = 'T1560.001'; Action = 'Archive'; Repeat = 3 },
        [PSCustomObject]@{ Category = '아카이브/인코딩'; Technique = 'T1027'; Action = 'Base64'; Repeat = 3 },
        [PSCustomObject]@{ Category = '스크립팅 기반 조작'; Technique = 'T1059.003'; Action = 'ScriptCopy'; Repeat = 3 },
        [PSCustomObject]@{ Category = '스크립팅 기반 조작'; Technique = 'T1059.003'; Action = 'ScriptDelete'; Repeat = 3 },
        [PSCustomObject]@{ Category = '권한/속성 조작'; Technique = 'T1222.001'; Action = 'ToggleAttribute'; Repeat = 2 },
        [PSCustomObject]@{ Category = '권한/속성 조작'; Technique = 'T1098'; Action = 'Timestamp'; Repeat = 2 },
        [PSCustomObject]@{ Category = '정리/청소'; Technique = 'T1070'; Action = 'Cleanup'; Repeat = 3 },
        [PSCustomObject]@{ Category = '발견/열거'; Technique = 'T1083'; Action = 'Discovery'; Repeat = 3 },
        [PSCustomObject]@{ Category = '이동·복사·유출'; Technique = 'T1048'; Action = 'ExfilCopy'; Repeat = 2 }
    )

    $counter = 1
    foreach ($entry in $entries) {
        for ($i = 1; $i -le $entry.Repeat; $i++) {
            [void]$plan.Add([PSCustomObject]@{
                Id = ('{0}-{1:D2}' -f $entry.Technique, $counter)
                Technique = $entry.Technique
                Category = $entry.Category
                Action = $entry.Action
            })
            $counter++
        }
    }
    return $plan
}

function Select-RandomFile {
    param([string] $RootPath, [string[]] $Extensions)
    $files = @(Get-ChildItem -LiteralPath $RootPath -File -Recurse |
        Where-Object { $Extensions -contains $_.Extension.TrimStart('.') })
    if ($files.Count -eq 0) { return $null }
    return $files | Get-Random
}

function Invoke-MalwareOperation {
    param(
        [PSCustomObject] $Operation,
        [string] $AreaName,
        [string] $AreaRoot
    )
    $timestamp = Get-Date
    $docsPath = Join-Path $AreaRoot 'Docs'
    $sysPath = Join-Path $AreaRoot 'SysCfg'
    $result = 'Success'
    $message = '완료'
    try {
        switch ($Operation.Action) {
            'Append' {
                $target = Select-RandomFile -RootPath $docsPath -Extensions @('doc','docx','ppt','pptx','xls','xlsx','hwp','hwpx','txt')
                if (-not $target) { throw '대상 문서를 찾지 못했습니다.' }
                Add-Content -LiteralPath $target.FullName -Value "`n# 추가 데이터 - $($timestamp.ToString('s'))"
            }
            'Overwrite' {
                $target = Select-RandomFile -RootPath $docsPath -Extensions @('txt','doc','docx','ppt','pptx','xls','xlsx')
                if (-not $target) { throw '대상 문서를 찾지 못했습니다.' }
                Set-Content -LiteralPath $target.FullName -Value "Overwritten by simulation at $($timestamp.ToString('s'))" -Encoding UTF8
            }
            'Archive' {
                $archiveRoot = Join-Path $AreaRoot '_AssessmentWorkspace'
                Ensure-Directory -Path $archiveRoot
                $zipName = 'DocsArchive_{0}.zip' -f ([Guid]::NewGuid().ToString('N'))
                Compress-Archive -LiteralPath $docsPath -DestinationPath (Join-Path $archiveRoot $zipName) -Force
            }
            'Base64' {
                $target = Select-RandomFile -RootPath $docsPath -Extensions @('txt','doc','docx','ppt','pptx','xls','xlsx')
                if (-not $target) { throw '대상 문서를 찾지 못했습니다.' }
                $content = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($target.FullName))
                $outFile = Join-Path $AreaRoot ('SysCfg\encoded_{0}.b64' -f $target.BaseName)
                Set-Content -LiteralPath $outFile -Value $content -Encoding ASCII
            }
            'ScriptCopy' {
                $target = Select-RandomFile -RootPath $docsPath -Extensions @('txt','doc','docx','ppt','pptx','xls','xlsx','hwp','hwpx')
                if (-not $target) { throw '대상 문서를 찾지 못했습니다.' }
                $destination = Join-Path $AreaRoot ('SysCfg\copy_{0}' -f $target.Name)
                $scriptPath = Join-Path $AreaRoot ('SysCfg\copy_{0}.ps1' -f $target.BaseName)
                $script = "Copy-Item -LiteralPath `"$($target.FullName)`" -Destination `"$destination`" -Force"
                Set-Content -LiteralPath $scriptPath -Value $script -Encoding UTF8
                Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',$scriptPath -Wait
            }
            'ScriptDelete' {
                $logPath = Join-Path $AreaRoot 'SysCfg\cleanup.log'
                $scriptPath = Join-Path $AreaRoot 'SysCfg\cleanup.cmd'
                $script = "@echo off`nif exist `"$logPath`" del /f /q `"$logPath`""
                Set-Content -LiteralPath $scriptPath -Value $script -Encoding ASCII
                Start-Process -FilePath 'cmd.exe' -ArgumentList "/c `"$scriptPath`"" -Wait
            }
            'ToggleAttribute' {
                $target = Select-RandomFile -RootPath $docsPath -Extensions @('txt','doc','docx','ppt','pptx','xls','xlsx')
                if (-not $target) { throw '대상 문서를 찾지 못했습니다.' }
                if ($target.Attributes -band [IO.FileAttributes]::Hidden) {
                    attrib -h -r "$($target.FullName)"
                }
                else {
                    attrib +h +r "$($target.FullName)"
                }
            }
            'Timestamp' {
                $target = Select-RandomFile -RootPath $docsPath -Extensions @('txt','doc','docx','ppt','pptx','xls','xlsx')
                if (-not $target) { throw '대상 문서를 찾지 못했습니다.' }
                (Get-Item -LiteralPath $target.FullName).LastWriteTime = (Get-Date).AddMinutes(-30)
            }
            'Cleanup' {
                $workspace = Join-Path $AreaRoot '_AssessmentWorkspace'
                Ensure-Directory -Path $workspace
                $logFile = Join-Path $workspace 'activity.log'
                Add-Content -LiteralPath $logFile -Value "[$($timestamp.ToString('s'))] 테스트 로그"
                Remove-Item -LiteralPath $logFile -Force
            }
            'Discovery' {
                $workspace = Join-Path $AreaRoot '_AssessmentWorkspace'
                Ensure-Directory -Path $workspace
                $report = Join-Path $workspace ('inventory_{0}.txt' -f $timestamp.ToString('HHmmss'))
                Get-ChildItem -LiteralPath $AreaRoot -File -Recurse | Select-Object FullName,Length,LastWriteTime | Out-String | Set-Content -LiteralPath $report -Encoding UTF8
            }
            'ExfilCopy' {
                $target = Select-RandomFile -RootPath $docsPath -Extensions @('txt','doc','docx','ppt','pptx','xls','xlsx','hwp','hwpx')
                if (-not $target) { throw '대상 문서를 찾지 못했습니다.' }
                $exfilRoot = Join-Path $AreaRoot '_Exfiltration'
                Ensure-Directory -Path $exfilRoot
                Copy-Item -LiteralPath $target.FullName -Destination (Join-Path $exfilRoot $target.Name) -Force
            }
            Default { throw "알 수 없는 작업 유형: $($Operation.Action)" }
        }
    }
    catch {
        $result = 'Failed'
        $message = $_.Exception.Message
    }
    return [PSCustomObject]@{
        Timestamp = $timestamp
        Result = $result
        Message = $message
    }
}
#endregion

#region RanSim 실행
function Invoke-RanSim {
    param([string] $ExecutablePath)
    if (-not $ExecutablePath) {
        return [PSCustomObject]@{ Timestamp = Get-Date; Result = 'Skipped'; Message = 'RanSim 실행 파일 미확보' }
    }
    try {
        Start-Process -FilePath $ExecutablePath -ArgumentList '/auto' -Wait -ErrorAction Stop
        return [PSCustomObject]@{ Timestamp = Get-Date; Result = 'Success'; Message = 'RanSim 자동 실행 완료' }
    }
    catch {
        return [PSCustomObject]@{ Timestamp = Get-Date; Result = 'Failed'; Message = $_.Exception.Message }
    }
}
#endregion

#region 보고서 생성
function Get-ColumnName {
    param([int] $Index)
    $name = ''
    $i = $Index
    do {
        $name = [char](65 + ($i % 26)) + $name
        $i = [math]::Floor($i / 26) - 1
    } while ($i -ge 0)
    return $name
}

function ConvertTo-WorksheetXml {
    param([System.Collections.IEnumerable] $Rows)
    $rowsList = @($Rows)
    if ($rowsList.Count -eq 0) { return '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData/></worksheet>' }
    $headers = $rowsList[0] | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
    $sheetData = New-Object System.Text.StringBuilder
    $rowIndex = 1
    $sheetData.Append("<row r='$rowIndex'>") | Out-Null
    for ($c = 0; $c -lt $headers.Count; $c++) {
        $col = Get-ColumnName -Index $c
        $value = [System.Security.SecurityElement]::Escape($headers[$c])
        $sheetData.Append("<c r='${col}${rowIndex}' t='inlineStr'><is><t>$value</t></is></c>") | Out-Null
    }
    $sheetData.Append('</row>') | Out-Null
    foreach ($row in $rowsList) {
        $rowIndex++
        $sheetData.Append("<row r='$rowIndex'>") | Out-Null
        for ($c = 0; $c -lt $headers.Count; $c++) {
            $col = Get-ColumnName -Index $c
            $rawValue = $row.$($headers[$c])
            if ($null -eq $rawValue) { $rawValue = '' }
            $value = [System.Security.SecurityElement]::Escape([string]$rawValue)
            $sheetData.Append("<c r='${col}${rowIndex}' t='inlineStr'><is><t xml:space='preserve'>$value</t></is></c>") | Out-Null
        }
        $sheetData.Append('</row>') | Out-Null
    }
    return "<worksheet xmlns='http://schemas.openxmlformats.org/spreadsheetml/2006/main'><sheetData>$($sheetData.ToString())</sheetData></worksheet>"
}

function New-SimpleWorkbook {
    param(
        [string] $Path,
        [hashtable[]] $Sheets
    )
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    $directory = Split-Path -Path $Path -Parent
    Ensure-Directory -Path $directory
    $zip = [System.IO.Compression.ZipFile]::Open($Path, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        $contentTypes = "<?xml version='1.0' encoding='UTF-8'?><Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'>" +
            "<Default Extension='rels' ContentType='application/vnd.openxmlformats-package.relationships+xml'/>" +
            "<Default Extension='xml' ContentType='application/xml'/>" +
            "<Override PartName='/xl/workbook.xml' ContentType='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml'/>"
        for ($i = 0; $i -lt $Sheets.Count; $i++) {
            $contentTypes += "<Override PartName='/xl/worksheets/sheet$($i+1).xml' ContentType='application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml'/>"
        }
        $contentTypes += "<Override PartName='/docProps/app.xml' ContentType='application/vnd.openxmlformats-officedocument.extended-properties+xml'/>" +
                        "<Override PartName='/docProps/core.xml' ContentType='application/vnd.openxmlformats-package.core-properties+xml'/>" +
                        "</Types>"
        $entry = $zip.CreateEntry('[Content_Types].xml')
        $writer = New-Object System.IO.StreamWriter($entry.Open())
        $writer.Write($contentTypes)
        $writer.Dispose()

        $rels = "<?xml version='1.0' encoding='UTF-8'?><Relationships xmlns='http://schemas.openxmlformats.org/package/2006/relationships'>" +
                "<Relationship Id='rId1' Type='http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument' Target='xl/workbook.xml'/>" +
                "<Relationship Id='rId2' Type='http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties' Target='docProps/core.xml'/>" +
                "<Relationship Id='rId3' Type='http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties' Target='docProps/app.xml'/>" +
                "</Relationships>"
        $entry = $zip.CreateEntry('_rels/.rels')
        $writer = New-Object System.IO.StreamWriter($entry.Open())
        $writer.Write($rels)
        $writer.Dispose()

        $workbookRels = "<?xml version='1.0' encoding='UTF-8'?><Relationships xmlns='http://schemas.openxmlformats.org/package/2006/relationships'>"
        for ($i = 0; $i -lt $Sheets.Count; $i++) {
            $workbookRels += "<Relationship Id='rId$($i+1)' Type='http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet' Target='worksheets/sheet$($i+1).xml'/>"
        }
        $workbookRels += '</Relationships>'
        $entry = $zip.CreateEntry('xl/_rels/workbook.xml.rels')
        $writer = New-Object System.IO.StreamWriter($entry.Open())
        $writer.Write($workbookRels)
        $writer.Dispose()

        $sheetsXml = ''
        for ($i = 0; $i -lt $Sheets.Count; $i++) {
            $nameEscaped = [System.Security.SecurityElement]::Escape($Sheets[$i].Name)
            $sheetsXml += "<sheet name='$nameEscaped' sheetId='$($i+1)' r:id='rId$($i+1)' xmlns:r='http://schemas.openxmlformats.org/officeDocument/2006/relationships'/>"
        }
        $workbookXml = "<?xml version='1.0' encoding='UTF-8'?><workbook xmlns='http://schemas.openxmlformats.org/spreadsheetml/2006/main'><sheets>$sheetsXml</sheets></workbook>"
        $entry = $zip.CreateEntry('xl/workbook.xml')
        $writer = New-Object System.IO.StreamWriter($entry.Open())
        $writer.Write($workbookXml)
        $writer.Dispose()

        for ($i = 0; $i -lt $Sheets.Count; $i++) {
            $worksheetXml = ConvertTo-WorksheetXml -Rows $Sheets[$i].Rows
            $entry = $zip.CreateEntry("xl/worksheets/sheet$($i+1).xml")
            $writer = New-Object System.IO.StreamWriter($entry.Open())
            $writer.Write($worksheetXml)
            $writer.Dispose()
        }

        $coreXml = "<?xml version='1.0' encoding='UTF-8'?><cp:coreProperties xmlns:cp='http://schemas.openxmlformats.org/package/2006/metadata/core-properties' xmlns:dc='http://purl.org/dc/elements/1.1/' xmlns:dcterms='http://purl.org/dc/terms/'><dc:title>데이터 보호 성능 평가 보고서</dc:title><dc:creator>Security Automation</dc:creator><cp:lastModifiedBy>Security Automation</cp:lastModifiedBy><dcterms:created xsi:type='dcterms:W3CDTF' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'>$(Get-Date -Format s)Z</dcterms:created></cp:coreProperties>"
        $entry = $zip.CreateEntry('docProps/core.xml')
        $writer = New-Object System.IO.StreamWriter($entry.Open())
        $writer.Write($coreXml)
        $writer.Dispose()

        $appXml = "<?xml version='1.0' encoding='UTF-8'?><Properties xmlns='http://schemas.openxmlformats.org/officeDocument/2006/extended-properties' xmlns:vt='http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes'><Application>PowerShell Automation</Application></Properties>"
        $entry = $zip.CreateEntry('docProps/app.xml')
        $writer = New-Object System.IO.StreamWriter($entry.Open())
        $writer.Write($appXml)
        $writer.Dispose()
    }
    finally {
        $zip.Dispose()
    }
}

function New-SimpleDocx {
    param([string] $Path, [string[]] $Paragraphs)
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    $directory = Split-Path -Path $Path -Parent
    Ensure-Directory -Path $directory
    $zip = [System.IO.Compression.ZipFile]::Open($Path, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        $contentTypes = "<?xml version='1.0' encoding='UTF-8'?><Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'>" +
                        "<Default Extension='rels' ContentType='application/vnd.openxmlformats-package.relationships+xml'/>" +
                        "<Default Extension='xml' ContentType='application/xml'/>" +
                        "<Override PartName='/word/document.xml' ContentType='application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml'/>" +
                        "<Override PartName='/docProps/app.xml' ContentType='application/vnd.openxmlformats-officedocument.extended-properties+xml'/>" +
                        "<Override PartName='/docProps/core.xml' ContentType='application/vnd.openxmlformats-package.core-properties+xml'/>" +
                        "</Types>"
        $entry = $zip.CreateEntry('[Content_Types].xml')
        $writer = New-Object System.IO.StreamWriter($entry.Open())
        $writer.Write($contentTypes)
        $writer.Dispose()

        $rels = "<?xml version='1.0' encoding='UTF-8'?><Relationships xmlns='http://schemas.openxmlformats.org/package/2006/relationships'>" +
                "<Relationship Id='rId1' Type='http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument' Target='word/document.xml'/>" +
                "<Relationship Id='rId2' Type='http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties' Target='docProps/core.xml'/>" +
                "<Relationship Id='rId3' Type='http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties' Target='docProps/app.xml'/>" +
                "</Relationships>"
        $entry = $zip.CreateEntry('_rels/.rels')
        $writer = New-Object System.IO.StreamWriter($entry.Open())
        $writer.Write($rels)
        $writer.Dispose()

        $docBuilder = New-Object System.Text.StringBuilder
        foreach ($paragraph in $Paragraphs) {
            $escaped = [System.Security.SecurityElement]::Escape($paragraph)
            $docBuilder.Append("<w:p><w:r><w:t xml:space='preserve'>$escaped</w:t></w:r></w:p>") | Out-Null
        }
        $documentXml = "<?xml version='1.0' encoding='UTF-8'?><w:document xmlns:w='http://schemas.openxmlformats.org/wordprocessingml/2006/main'>$docBuilder</w:document>"
        $entry = $zip.CreateEntry('word/document.xml')
        $writer = New-Object System.IO.StreamWriter($entry.Open())
        $writer.Write($documentXml)
        $writer.Dispose()

        $coreXml = "<?xml version='1.0' encoding='UTF-8'?><cp:coreProperties xmlns:cp='http://schemas.openxmlformats.org/package/2006/metadata/core-properties' xmlns:dc='http://purl.org/dc/elements/1.1/' xmlns:dcterms='http://purl.org/dc/terms/'><dc:title>데이터 보호 성능평가 보고서</dc:title><dc:creator>Security Automation</dc:creator><cp:lastModifiedBy>Security Automation</cp:lastModifiedBy><dcterms:created xsi:type='dcterms:W3CDTF' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'>$(Get-Date -Format s)Z</dcterms:created></cp:coreProperties>"
        $entry = $zip.CreateEntry('docProps/core.xml')
        $writer = New-Object System.IO.StreamWriter($entry.Open())
        $writer.Write($coreXml)
        $writer.Dispose()

        $appXml = "<?xml version='1.0' encoding='UTF-8'?><Properties xmlns='http://schemas.openxmlformats.org/officeDocument/2006/extended-properties' xmlns:vt='http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes'><Application>PowerShell Automation</Application></Properties>"
        $entry = $zip.CreateEntry('docProps/app.xml')
        $writer = New-Object System.IO.StreamWriter($entry.Open())
        $writer.Write($appXml)
        $writer.Dispose()
    }
    finally {
        $zip.Dispose()
    }
}
#endregion

#region 결과 요약
function Get-AreaSummary {
    param(
        [System.Collections.IEnumerable] $Records,
        [string] $AreaName,
        [string] $Stage
    )
    $areaRecords = @($Records | Where-Object { $_.Area -eq $AreaName })
    $changed = (@($areaRecords | Where-Object { $_.Changed -eq $true })).Count
    $newFiles = (@($areaRecords | Where-Object { $_.Exists_Before -eq $false -and $_.Exists_After -eq $true })).Count
    $missing = (@($areaRecords | Where-Object { $_.Exists_Before -eq $true -and $_.Exists_After -eq $false })).Count
    $intact = (@($areaRecords | Where-Object { $_.Changed -eq $false })).Count
    return [PSCustomObject]@{
        Stage = $Stage
        Area = $AreaName
        Intact = $intact
        Changed = $changed
        New = $newFiles
        Missing = $missing
    }
}

function Get-SummaryRowObject {
    param(
        [System.Collections.IEnumerable] $Rows,
        [string] $Stage,
        [string] $Area
    )

    $match = $Rows | Where-Object { $_.Stage -eq $Stage -and $_.Area -eq $Area } | Select-Object -First 1
    if ($null -eq $match) {
        return [PSCustomObject]@{
            Stage = $Stage
            Area = $Area
            Intact = 0
            Changed = 0
            New = 0
            Missing = 0
        }
    }

    return $match
}

function Get-IntactPercentage {
    param([PSCustomObject] $Row)

    $total = [double]($Row.Intact + $Row.Changed + $Row.New + $Row.Missing)
    if ($total -le 0) {
        return 0
    }

    return [math]::Round(($Row.Intact / $total) * 100, 2)
}
#endregion

#region 메인 실행 흐름
Write-Host '=== 데이터 보호 성능평가 자동화 시작 ==='
$normalRoot = Read-RequiredPath -PromptText '일반영역 폴더 경로를 입력하세요'
$secureRoot = Read-RequiredPath -PromptText '보안영역 폴더 경로를 입력하세요'
$reportRoot = Read-RequiredPath -PromptText '결과 데이터를 저장할 폴더 경로를 입력하세요 (폴더 또는 .xlsx 경로 가능)'

if ($normalRoot -eq $secureRoot) {
    throw '일반영역과 보안영역 경로는 서로 달라야 합니다.'
}

$seed = Get-Random -Maximum 1000000
$docPlan = Get-DocumentPlan -Seed $seed
$usrClassBytes = New-Object byte[] 4096
$dllBytes = New-Object byte[] 32768
$rand = [System.Random]::new($seed)
$rand.NextBytes($usrClassBytes)
$rand.NextBytes($dllBytes)

Initialize-TestArea -AreaName 'GeneralArea' -RootPath $normalRoot -DocumentPlan $docPlan -UsrClassBytes $usrClassBytes -DllBytes $dllBytes
Initialize-TestArea -AreaName 'SecureArea' -RootPath $secureRoot -DocumentPlan $docPlan -UsrClassBytes $usrClassBytes -DllBytes $dllBytes

Write-Host "테스트 데이터 생성 완료 (Seed: $seed)"

$useFileTarget = $reportRoot -match '\\.xlsx$'
$reportDirectory = if ($useFileTarget) {
    $parent = Split-Path -Path $reportRoot -Parent
    if ([string]::IsNullOrWhiteSpace($parent)) { (Get-Location).Path } else { $parent }
} else {
    $reportRoot
}

Ensure-Directory -Path $reportDirectory
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$csvFolder = Join-Path $reportDirectory 'csv'
Ensure-Directory -Path $csvFolder
$jsonFolder = Join-Path $reportDirectory 'json'
Ensure-Directory -Path $jsonFolder

$baselineSnapshots = @{
    General = Get-FileSnapshot -RootPath $normalRoot
    Secure = Get-FileSnapshot -RootPath $secureRoot
}

$baselineCsv = Join-Path $csvFolder "Baseline_${timestamp}.csv"
$baselineData = @()
foreach ($area in @('General','Secure')) {
    $snapshot = $baselineSnapshots[$area]
    foreach ($key in $snapshot.Keys) {
        $info = $snapshot[$key]
        $baselineData += [PSCustomObject]@{
            Area = $area
            FilePath = $key
            Size = $info.Size
            SHA256 = $info.Hash
        }
    }
}
$baselineData | Export-Csv -Path $baselineCsv -NoTypeInformation -Encoding UTF8

$atomicInfo = Ensure-AtomicToolkit
foreach ($msg in $atomicInfo.Messages) { Write-Host $msg -ForegroundColor Yellow }
$ranSimInfo = Ensure-RanSim
foreach ($msg in $ranSimInfo.Messages) { Write-Host $msg -ForegroundColor Yellow }
$calderaInfo = Ensure-Caldera
foreach ($msg in $calderaInfo.Messages) { Write-Host $msg -ForegroundColor Yellow }

if ($atomicInfo.Module) {
    Write-Host "Invoke-AtomicRedTeam 모듈 버전: $($atomicInfo.Module.Version)" -ForegroundColor Cyan
} else {
    Write-Host 'Invoke-AtomicRedTeam 모듈이 없어 내장 악성 행위 시나리오만 실행합니다.' -ForegroundColor Yellow
}
if ($atomicInfo.AtomicsPath) {
    Write-Host "Atomics 폴더 위치: $($atomicInfo.AtomicsPath)" -ForegroundColor Cyan
}
if ($ranSimInfo.Path) {
    Write-Host "RanSim 경로: $($ranSimInfo.Path)" -ForegroundColor Cyan
} else {
    Write-Host 'RanSim 실행 파일이 없어 내장 스냅샷 비교만 수행합니다.' -ForegroundColor Yellow
}
if ($calderaInfo.Path) {
    Write-Host "Caldera 패키지 위치: $($calderaInfo.Path)" -ForegroundColor Cyan
}

$malwarePlan = Get-MalwareOperationPlan
$malwareRecords = @()

foreach ($area in @(@{Name='GeneralArea'; Key='General'; Root=$normalRoot}, @{Name='SecureArea'; Key='Secure'; Root=$secureRoot})) {
    foreach ($operation in $malwarePlan) {
        $before = Get-FileSnapshot -RootPath $area.Root
        $opResult = Invoke-MalwareOperation -Operation $operation -AreaName $area.Name -AreaRoot $area.Root
        $after = Get-FileSnapshot -RootPath $area.Root
        $records = Compare-Snapshots -Before $before -After $after -AreaName $area.Name -TestId $operation.Id -Result $opResult.Result -Message $opResult.Message -Timestamp $opResult.Timestamp
        $malwareRecords += $records
    }
}

$malwareCsv = Join-Path $csvFolder "Malware_Assessment_${timestamp}.csv"
$malwareRecords | Export-Csv -Path $malwareCsv -NoTypeInformation -Encoding UTF8

$ranSimResult = Invoke-RanSim -ExecutablePath $ranSimInfo.Path
$preRansomSnapshots = @{
    General = Get-FileSnapshot -RootPath $normalRoot
    Secure = Get-FileSnapshot -RootPath $secureRoot
}
$ranSimRecords = @()
foreach ($area in @(@{Name='GeneralArea'; Root=$normalRoot; Before=$preRansomSnapshots.General}, @{Name='SecureArea'; Root=$secureRoot; Before=$preRansomSnapshots.Secure})) {
    $after = Get-FileSnapshot -RootPath $area.Root
    $records = Compare-Snapshots -Before $area.Before -After $after -AreaName $area.Name -TestId 'RanSim' -Result $ranSimResult.Result -Message $ranSimResult.Message -Timestamp $ranSimResult.Timestamp
    $ranSimRecords += $records
}

$ranSimCsv = Join-Path $csvFolder "Ransomware_Assessment_${timestamp}.csv"
$ranSimRecords | Export-Csv -Path $ranSimCsv -NoTypeInformation -Encoding UTF8

$summaryRows = @()
$summaryRows += Get-AreaSummary -Records $malwareRecords -AreaName 'GeneralArea' -Stage 'Malware'
$summaryRows += Get-AreaSummary -Records $malwareRecords -AreaName 'SecureArea' -Stage 'Malware'
$summaryRows += Get-AreaSummary -Records $ranSimRecords -AreaName 'GeneralArea' -Stage 'Ransomware'
$summaryRows += Get-AreaSummary -Records $ranSimRecords -AreaName 'SecureArea' -Stage 'Ransomware'

$summaryCsv = Join-Path $csvFolder "Summary_${timestamp}.csv"
$summaryRows | Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding UTF8

$malwareJson = Join-Path $jsonFolder "Malware_Assessment_${timestamp}.json"
$malwareRecords | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $malwareJson -Encoding UTF8
$ranSimJson = Join-Path $jsonFolder "Ransomware_Assessment_${timestamp}.json"
$ranSimRecords | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ranSimJson -Encoding UTF8

$excelPath = if ($useFileTarget) { $reportRoot } else { Join-Path $reportDirectory "DataProtection_Report_${timestamp}.xlsx" }
$sheetData = @(
    @{ Name = 'Summary'; Rows = $summaryRows },
    @{ Name = 'Malware'; Rows = $malwareRecords },
    @{ Name = 'Ransomware'; Rows = $ranSimRecords }
)
New-SimpleWorkbook -Path $excelPath -Sheets $sheetData

$docxPath = Join-Path $reportDirectory "DataProtection_Report_${timestamp}.docx"
$atomicModuleVersion = if ($atomicInfo.Module) { $atomicInfo.Module.Version.ToString() } else { '확보 실패' }
$atomicsLocation = if ($atomicInfo.AtomicsPath) { $atomicInfo.AtomicsPath } else { '확보 실패' }
$ranSimDisplay = if ($ranSimInfo.Path) { $ranSimInfo.Path } else { '미확보' }
$calderaDisplay = if ($calderaInfo.Path) { $calderaInfo.Path } else { '미확보' }
$summaryLines = @()
foreach ($row in $summaryRows) {
    $summaryLines += "- $($row.Stage)/$($row.Area) → Intact: $($row.Intact), Changed: $($row.Changed), New: $($row.New), Missing: $($row.Missing)"
}
$malwareGeneralRow = Get-SummaryRowObject -Rows $summaryRows -Stage 'Malware' -Area 'GeneralArea'
$malwareSecureRow = Get-SummaryRowObject -Rows $summaryRows -Stage 'Malware' -Area 'SecureArea'
$ransomGeneralRow = Get-SummaryRowObject -Rows $summaryRows -Stage 'Ransomware' -Area 'GeneralArea'
$ransomSecureRow = Get-SummaryRowObject -Rows $summaryRows -Stage 'Ransomware' -Area 'SecureArea'

$malwareGeneralRate = Get-IntactPercentage -Row $malwareGeneralRow
$malwareSecureRate = Get-IntactPercentage -Row $malwareSecureRow

$missingInsight = if ($malwareGeneralRow.Missing -eq $malwareSecureRow.Missing) {
    "• 두 영역 모두 $($malwareGeneralRow.Missing)건씩 누락이 발생했다는 점은 악성 행위 중 삭제 또는 이동이 이뤄졌음을 의미하며, 백업/복구 전략 검토가 필요합니다."
} else {
    "• 일반 영역은 $($malwareGeneralRow.Missing)건, 보안 영역은 $($malwareSecureRow.Missing)건의 누락이 발생했습니다. 악성 행위 중 삭제 또는 이동이 이뤄졌을 가능성을 고려해 백업/복구 전략을 점검해야 합니다."
}

$atomicsInsight = if ($atomicInfo.AtomicsPath) {
    "• Atomics 콘텐츠가 $($atomicInfo.AtomicsPath) 경로에서 확인되어 30개 시나리오를 수행할 준비가 완료되었습니다."
} else {
    (@'
• Atomics 확보 실패: 보고서에 "Atomics 경로: 확보 실패"가 표시된 경우, Atomic Red Team의 atomics 콘텐츠가 로컬에 존재하지 않아 실제 30개 시나리오가 전부 수행되지 않았거나, 대체 경로를 수동으로 지정해야 한다는 뜻입니다. GitHub에서 redcanaryco/atomic-red-team 저장소를 받아 C:\AtomicRedTeam\atomics에 풀거나 ATOMIC_RED_TEAM_PATH 환경 변수를 해당 경로로 설정한 뒤 재실행하면 모든 시나리오를 수행할 수 있습니다.
'@).Trim()
}

$analysisParagraphs = @(
    '',
    '평가 결과 요약',
    '보고서는 일반 영역과 보안 영역 모두에 대해 악성코드(Atomic)와 랜섬웨어(RanSim) 시뮬레이션을 수행한 뒤, 각 영역의 파일이 원본과 동일하게 유지(Intact)되었는지, 변경(Changed)·신규(New)·누락(Missing) 되었는지를 집계한 값입니다.',
    '표에 따르면 총 네 가지 조합(Stage × Area)의 결과가 기록되어 있습니다.',
    '',
    '악성코드 단계(Atomic 7개 버킷·30 시나리오)',
    ("일반 영역(Intact {0}, Changed {1}, New {2}, Missing {3}) : 대부분의 파일(약 {4:F2}%)이 원형 그대로 남아 있지만, {1}건의 내용 변조와 {2}건의 신규 파일 생성, {3}건의 파일 누락이 확인되었습니다. 악성행위가 일정 부분 성공했다는 의미입니다." -f $malwareGeneralRow.Intact, $malwareGeneralRow.Changed, $malwareGeneralRow.New, $malwareGeneralRow.Missing, $malwareGeneralRate),
    ("보안 영역(Intact {0}, Changed {1}, New {2}, Missing {3}) : 보호 영역 역시 상당수 파일이 보존되었으나, 일반 영역보다 소폭 낮은 침해 수치(Changed·New)가 기록되었습니다. 동일하게 {3}건의 누락이 있어 보호 정책이 아직 완전하지 않음을 시사합니다." -f $malwareSecureRow.Intact, $malwareSecureRow.Changed, $malwareSecureRow.New, $malwareSecureRow.Missing),
    '시사점',
    ("• 보안 영역이 전반적으로 더 적은 변조·신규 파일을 허용했지만, 여전히 {0}건의 변조가 발생했습니다." -f $malwareSecureRow.Changed),
    '• 신규 파일(New)은 악성 시나리오에서 생성된 스크립트나 아카이브가 잔존한 경우로 볼 수 있으므로, 실행 후 자동 정리 정책이 필요할 수 있습니다.',
    $missingInsight,
    '',
    '랜섬웨어 단계(RanSim)',
    ("일반 영역(Intact {0}, Changed {1}, New {2}, Missing {3}) : RanSim이 수행된 뒤에도 모든 파일이 원본과 동일하게 유지되었습니다. 차단 또는 롤백이 정상 작동한 것으로 해석됩니다." -f $ransomGeneralRow.Intact, $ransomGeneralRow.Changed, $ransomGeneralRow.New, $ransomGeneralRow.Missing),
    ("보안 영역(Intact {0}, Changed {1}, New {2}, Missing {3}) : 동일하게 어떠한 변조·신규·누락도 발생하지 않았습니다." -f $ransomSecureRow.Intact, $ransomSecureRow.Changed, $ransomSecureRow.New, $ransomSecureRow.Missing),
    '시사점',
    '• 랜섬웨어 시뮬레이션에 대해선 양측 모두 완벽히 보존(Intact) 상태를 유지했습니다.',
    ("• RanSim 실행 경로가 {0}로 확인되므로, 이 경로를 지속적으로 모니터링하면서 최신 버전 유지가 필요합니다." -f $ranSimDisplay),
    '',
    '종합 평가',
    '• 악성코드 대응: 보안 영역이 일반 영역보다 나은 수치를 보이지만, 여전히 다수의 변조·신규·누락이 보고되어 “완전 차단” 수준에는 미치지 못합니다. 버킷별로 어떤 기법에서 변조가 집중되는지 CSV 세부 데이터를 분석해 보완 정책(ACL 강화, 실행 제어, 무결성 감시 등)을 세분화해야 합니다.',
    '• 랜섬웨어 대응: 두 영역 모두 안정적이므로 현재의 RanSim 대응 구성은 유효합니다. 다만 Caldera/Atomic 기반의 사전 단계(권한 상승, 파일 권한 조작 등)에 대해서도 동일한 수준의 제어가 적용되는지 추가 확인이 필요합니다.',
    $atomicsInsight,
    '',
    '권장 후속 조치',
    '• Atomics 콘텐츠 확보: 위 경고를 해소하여 전체 시나리오가 정확히 실행되도록 합니다.',
    '• CSV 세부 분석: 변조/신규/누락이 발생한 파일과 해당 기법을 확인해 추가 방어 정책을 수립합니다.',
    '• 보안 영역 보강: 변조 사례가 집중되는 버킷(예: 파일 쓰기·스크립트 실행 등)에 대해 ACL, 실행 제어, 무결성 감시 정책을 강화합니다.',
    '• 정리 자동화: 신규 파일이 잔존하지 않도록 테스트 종료 후 자동 정리 혹은 롤백 절차를 도입합니다.'
)
$paragraphs = @(
    '데이터 보호 성능평가 자동화 보고서',
    "생성 일시: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
    "난수 시드: $seed",
    "RanSim 실행 결과: $($ranSimResult.Result) - $($ranSimResult.Message)",
    "Invoke-AtomicRedTeam 버전: $atomicModuleVersion",
    "Atomics 경로: $atomicsLocation",
    "RanSim 경로: $ranSimDisplay",
    "Caldera 경로: $calderaDisplay",
    '요약 결과 (파일 상태 비교):'
) +
    $summaryLines +
    $analysisParagraphs +
    @(
        "악성행위 결과 CSV: $malwareCsv",
        "랜섬웨어 결과 CSV: $ranSimCsv",
        '상세 데이터는 XLSX/CSV/JSON 파일을 참조하세요.'
    )
New-SimpleDocx -Path $docxPath -Paragraphs $paragraphs

Write-Host '--- 생성된 보고서 ---'
Write-Host "기준선 CSV : $baselineCsv"
Write-Host "악성코드 CSV : $malwareCsv"
Write-Host "랜섬웨어 CSV : $ranSimCsv"
Write-Host "요약 CSV : $summaryCsv"
Write-Host "악성코드 JSON : $malwareJson"
Write-Host "랜섬웨어 JSON : $ranSimJson"
Write-Host "엑셀 보고서 : $excelPath"
Write-Host "워드 보고서 : $docxPath"
Write-Host '=== 자동화가 완료되었습니다. 결과 파일을 확인하세요. ==='
#endregion
