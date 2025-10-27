<#
.SYNOPSIS
    Automates creation of sample data, ransomware simulator checks, and compromise validation for secure and general folders.

.DESCRIPTION
    This script prompts for secure and general area locations along with a folder for results. It generates sample
    documents and system-like data in each area, captures baseline integrity information, verifies the presence of
    ransomware simulation tooling (RanSim, Atomic Red Team/Invoke-Atomic, and Caldera), optionally assists with
    downloading or launching their installers, and finally evaluates the areas for potential compromise by comparing
    file integrity snapshots. The findings are exported to a CSV report.

.NOTES
    Run from an elevated PowerShell session.
    Only execute ransomware simulations inside an authorized test environment.
#>
[CmdletBinding()]
param()

function Read-ValidatedPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Prompt,

        [Parameter()]
        [switch]$AllowCreate,

        [Parameter()]
        [ValidateSet('FileSystem','Directory')]
        [string]$Type = 'Directory'
    )

    while ($true) {
        $inputPath = Read-Host $Prompt
        if ([string]::IsNullOrWhiteSpace($inputPath)) {
            Write-Warning '경로를 입력해야 합니다.'
            continue
        }
        $resolved = Resolve-Path -Path $inputPath -ErrorAction SilentlyContinue
        if (-not $resolved) {
            if ($AllowCreate) {
                try {
                    New-Item -Path $inputPath -ItemType Directory -Force | Out-Null
                    $resolved = Resolve-Path -Path $inputPath
                }
                catch {
                    Write-Warning "경로를 생성할 수 없습니다: $($_.Exception.Message)"
                    continue
                }
            }
            else {
                Write-Warning '존재하지 않는 경로입니다. 다시 입력해 주세요.'
                continue
            }
        }
        if ($Type -eq 'Directory' -and -not (Test-Path -LiteralPath $resolved -PathType Container)) {
            Write-Warning '폴더 경로를 입력해야 합니다.'
            continue
        }
        return $resolved.ProviderPath
    }
}

function Initialize-AreaData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AreaName,
        [Parameter(Mandatory)][string]$TargetPath
    )

    Write-Verbose "[$AreaName] 샘플 데이터를 생성하는 중입니다."
    $documentDir = Join-Path $TargetPath 'Documents'
    $systemDir   = Join-Path $TargetPath 'System'
    New-Item -ItemType Directory -Path $documentDir,$systemDir -Force | Out-Null

    $docExtensions = 'doc','docx','ppt','pptx','xls','xlsx','hwp','hwpx','txt','pdf'
    foreach ($ext in $docExtensions) {
        $filePath = Join-Path $documentDir "${AreaName}_Sample.${ext}"
        if (-not (Test-Path -LiteralPath $filePath)) {
            "${AreaName} 문서 샘플 (${ext}) - $(Get-Date -Format o)" | Set-Content -Path $filePath -Encoding UTF8
        }
    }

    $systemSamples = @(
        @{ Name = 'system_config.json'; Content = @{ Service = 'LineOfBusinessApp'; Version = '1.0.0'; Maintainer = 'SecurityTeam' } | ConvertTo-Json -Depth 3 },
        @{ Name = 'environment.ini'; Content = "[Environment]`nZone=$AreaName`nGenerated=$(Get-Date -Format o)" },
        @{ Name = 'sensitive_list.csv'; Content = "Key,Value`nApiKey,REDACTED-$AreaName`nDatabase,Primary-$AreaName" }
    )
    foreach ($sample in $systemSamples) {
        $path = Join-Path $systemDir $sample.Name
        if (-not (Test-Path -LiteralPath $path)) {
            $sample.Content | Set-Content -Path $path -Encoding UTF8
        }
    }
}

function Get-AreaSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AreaPath,
        [Parameter(Mandatory)][string]$AreaName
    )

    Write-Verbose "[$AreaName] 파일 무결성 스냅샷을 수집하는 중입니다."
    $files = Get-ChildItem -Path $AreaPath -File -Recurse -ErrorAction SilentlyContinue
    $snapshot = @{}
    foreach ($file in $files) {
        try {
            $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256
            $relative = $file.FullName.Substring($AreaPath.Length).TrimStart('\\')
            $snapshot[$relative] = [pscustomobject]@{
                Path           = $file.FullName
                RelativePath   = $relative
                Hash           = $hash.Hash
                Length         = $file.Length
                LastWriteTime  = $file.LastWriteTimeUtc
                Extension      = $file.Extension
            }
        }
        catch {
            Write-Warning "[$AreaName] $($file.FullName) 해시를 계산하지 못했습니다: $($_.Exception.Message)"
        }
    }
    return $snapshot
}

function Compare-AreaSnapshots {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Baseline,
        [Parameter(Mandatory)]$Current,
        [Parameter(Mandatory)][string]$AreaName
    )

    $modified = @()
    $missing  = @()
    $newFiles = @()

    foreach ($key in $Baseline.Keys) {
        if (-not $Current.ContainsKey($key)) {
            $missing += $Baseline[$key]
            continue
        }
        $baseEntry = $Baseline[$key]
        $curEntry  = $Current[$key]
        if ($baseEntry.Hash -ne $curEntry.Hash) {
            $modified += [pscustomobject]@{
                RelativePath = $key
                PreviousHash = $baseEntry.Hash
                CurrentHash  = $curEntry.Hash
                Comment      = '내용 변경 또는 암호화 가능성'
            }
        }
        elseif ($baseEntry.Extension -ne $curEntry.Extension) {
            $modified += [pscustomobject]@{
                RelativePath = $key
                PreviousHash = $baseEntry.Hash
                CurrentHash  = $curEntry.Hash
                Comment      = '확장자 변경 탐지'
            }
        }
    }

    foreach ($key in $Current.Keys) {
        if (-not $Baseline.ContainsKey($key)) {
            $newFiles += $Current[$key]
        }
    }

    $suspiciousCount = $modified.Count + $missing.Count
    $isCompromised = $suspiciousCount -gt 0
    $notes = @()
    if ($modified.Count -gt 0) { $notes += "변경 파일 ${($modified.Count)}건" }
    if ($missing.Count  -gt 0) { $notes += "누락 파일 ${($missing.Count)}건" }
    if ($newFiles.Count -gt 0) { $notes += "신규 파일 ${($newFiles.Count)}건" }

    return [pscustomobject]@{
        AreaName        = $AreaName
        ModifiedCount   = $modified.Count
        MissingCount    = $missing.Count
        NewFileCount    = $newFiles.Count
        IsCompromised   = $isCompromised
        Notes           = ($notes -join '; ')
        ModifiedDetails = $modified
        MissingDetails  = $missing
        NewFileDetails  = $newFiles
    }
}

function Ensure-RanSim {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$StagingPath
    )

    $candidatePaths = @(
        'C:\\Program Files (x86)\\KnowBe4\\RanSim\\RanSim.exe',
        'C:\\Program Files\\KnowBe4\\RanSim\\RanSim.exe'
    )
    foreach ($path in $candidatePaths) {
        if (Test-Path -LiteralPath $path) {
            Write-Host 'RanSim이 설치되어 있습니다.' -ForegroundColor Green
            return $path
        }
    }

    Write-Warning 'RanSim이 설치되어 있지 않습니다. 공식 다운로드 페이지에서 설치를 진행합니다.'
    $downloadUrl = 'https://downloads.knowbe4.com/ransim/KnowBe4RanSim.zip'
    $localZip    = Join-Path $StagingPath 'KnowBe4RanSim.zip'
    $shouldDownload = Read-Host 'RanSim 패키지를 자동으로 다운로드하시겠습니까? (y/n)'
    if ($shouldDownload -match '^[Yy]') {
        try {
            Invoke-WebRequest -Uri $downloadUrl -OutFile $localZip -UseBasicParsing
            Write-Host "RanSim 설치 패키지를 다운로드했습니다: $localZip"
            Expand-Archive -Path $localZip -DestinationPath $StagingPath -Force
            $installer = Get-ChildItem -Path $StagingPath -Filter 'RanSim*.msi' -Recurse | Select-Object -First 1
            if ($null -ne $installer) {
                Write-Host 'RanSim 설치 관리자를 실행합니다 (수동 설치 필요).' -ForegroundColor Yellow
                Start-Process msiexec.exe -ArgumentList "/i `"$($installer.FullName)`"" -Verb RunAs
            }
            else {
                Write-Warning 'RanSim 설치 파일을 찾지 못했습니다. 압축 해제된 폴더를 확인하세요.'
            }
        }
        catch {
            Write-Warning "RanSim 다운로드 중 오류 발생: $($_.Exception.Message)"
        }
    }
    else {
        Write-Host 'RanSim 다운로드를 건너뜁니다. 공식 사이트에서 직접 설치하세요.'
    }
    return $null
}

function Ensure-AtomicRedTeam {
    [CmdletBinding()]
    param()

    $module = Get-Module -ListAvailable -Name Invoke-AtomicRedTeam
    if ($module) {
        Write-Host 'Invoke-AtomicRedTeam 모듈이 확인되었습니다.' -ForegroundColor Green
        return $true
    }

    Write-Warning 'Invoke-AtomicRedTeam 모듈이 없습니다. PowerShell 갤러리에서 설치합니다.'
    $consent = Read-Host 'Invoke-AtomicRedTeam 모듈을 설치하시겠습니까? (y/n)'
    if ($consent -match '^[Yy]') {
        try {
            Install-Module -Name Invoke-AtomicRedTeam -Scope AllUsers -Force
            Write-Host 'Invoke-AtomicRedTeam 모듈 설치가 완료되었습니다.' -ForegroundColor Green
            return $true
        }
        catch {
            Write-Warning "Invoke-AtomicRedTeam 설치 실패: $($_.Exception.Message)"
        }
    }
    else {
        Write-Host '모듈 설치를 건너뜁니다. 추후 수동으로 설치하세요.'
    }
    return $false
}

function Ensure-Caldera {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$StagingPath
    )

    $defaultPath = 'C:\\Caldera'
    if (Test-Path -LiteralPath $defaultPath) {
        Write-Host 'Caldera 서버 디렉터리가 발견되었습니다.' -ForegroundColor Green
        return $defaultPath
    }

    Write-Warning 'Caldera가 설치되어 있지 않습니다. GitHub 릴리스를 내려받아 설정합니다.'
    $downloadUrl = 'https://github.com/mitre/caldera/archive/refs/heads/master.zip'
    $localZip    = Join-Path $StagingPath 'caldera-master.zip'
    $consent = Read-Host 'Caldera 패키지를 다운로드하시겠습니까? (y/n)'
    if ($consent -match '^[Yy]') {
        try {
            Invoke-WebRequest -Uri $downloadUrl -OutFile $localZip -UseBasicParsing
            Write-Host "Caldera 패키지를 다운로드했습니다: $localZip"
            $destination = Join-Path $StagingPath 'caldera-master'
            Expand-Archive -Path $localZip -DestinationPath $destination -Force
            Write-Host 'Caldera 압축을 해제했습니다. Python 환경 구성이 필요합니다. README를 참고하세요.' -ForegroundColor Yellow
            return $destination
        }
        catch {
            Write-Warning "Caldera 다운로드 실패: $($_.Exception.Message)"
        }
    }
    else {
        Write-Host 'Caldera 다운로드를 건너뜁니다. 수동으로 설치하세요.'
    }
    return $null
}

function Evaluate-Areas {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Areas,
        [Parameter(Mandatory)]$Baselines
    )

    $results = @()
    foreach ($area in $Areas) {
        Write-Host "[$($area.Name)] 랜섬웨어 침해 여부를 측정합니다." -ForegroundColor Cyan
        $currentSnapshot = Get-AreaSnapshot -AreaPath $area.Path -AreaName $area.Name
        $result = Compare-AreaSnapshots -Baseline $Baselines[$area.Name] -Current $currentSnapshot -AreaName $area.Name
        $results += $result

        if ($result.IsCompromised) {
            Write-Warning "[$($area.Name)] 의심스러운 변경 사항이 탐지되었습니다."
        }
        else {
            Write-Host "[$($area.Name)] 변경 사항 없음." -ForegroundColor Green
        }
    }
    return $results
}

Write-Host '=== 랜섬웨어 검증 자동화 시작 ===' -ForegroundColor Cyan
$generalPath = Read-ValidatedPath -Prompt '일반영역 폴더 경로를 입력하세요' -Type Directory -AllowCreate
$securePath  = Read-ValidatedPath -Prompt '보안영역 폴더 경로를 입력하세요' -Type Directory -AllowCreate
$reportPath  = Read-ValidatedPath -Prompt '결과 데이터를 저장할 폴더 경로를 입력하세요' -Type Directory -AllowCreate

$areas = @(
    [pscustomobject]@{ Name = 'GeneralArea'; Path = $generalPath },
    [pscustomobject]@{ Name = 'SecureArea';  Path = $securePath }
)

foreach ($area in $areas) {
    Initialize-AreaData -AreaName $area.Name -TargetPath $area.Path
}

$baselines = @{}
foreach ($area in $areas) {
    $baselines[$area.Name] = Get-AreaSnapshot -AreaPath $area.Path -AreaName $area.Name
}

Write-Host '기본 무결성 스냅샷을 완료했습니다. 시뮬레이터 준비 상태를 확인합니다.' -ForegroundColor Cyan
$staging = Join-Path $reportPath "SimulatorPackages_$(Get-Date -Format yyyyMMddHHmmss)"
New-Item -ItemType Directory -Path $staging -Force | Out-Null

$ransomExe = Ensure-RanSim -StagingPath $staging
$atomicReady = Ensure-AtomicRedTeam
$calderaPath = Ensure-Caldera -StagingPath $staging

Write-Host '각 시뮬레이터를 통해 랜섬웨어 시나리오를 실행한 뒤 Enter 키를 눌러 계속하세요.' -ForegroundColor Yellow
Write-Host 'RanSim 시나리오 실행 완료 후 Enter: ' -NoNewline
[void][System.Console]::ReadLine()
Write-Host 'Atomic Red Team/Caldera 기반 테스트 실행 완료 후 Enter: ' -NoNewline
[void][System.Console]::ReadLine()

$evaluation = Evaluate-Areas -Areas $areas -Baselines $baselines

$csvPath = Join-Path $reportPath ("Ransomware_Evaluation_{0}.csv" -f (Get-Date -Format yyyyMMdd_HHmmss))
$flatReport = foreach ($item in $evaluation) {
    [pscustomobject]@{
        Timestamp       = (Get-Date)
        AreaName        = $item.AreaName
        ModifiedFiles   = $item.ModifiedCount
        MissingFiles    = $item.MissingCount
        NewFiles        = $item.NewFileCount
        Compromised     = $item.IsCompromised
        Notes           = $item.Notes
    }
}
$flatReport | Export-Csv -Path $csvPath -Encoding UTF8 -NoTypeInformation
Write-Host "결과 CSV 파일을 생성했습니다: $csvPath" -ForegroundColor Green

$detailPath = Join-Path $reportPath ("Ransomware_Evaluation_Details_{0}.json" -f (Get-Date -Format yyyyMMdd_HHmmss))
$evaluation | ConvertTo-Json -Depth 5 | Set-Content -Path $detailPath -Encoding UTF8
Write-Host "세부 JSON 데이터를 생성했습니다: $detailPath" -ForegroundColor Green

Write-Host '=== 검증이 완료되었습니다. 결과 파일을 확인하세요. ===' -ForegroundColor Cyan