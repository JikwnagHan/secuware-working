<#
.SYNOPSIS
    보안영역과 일반영역에 예제 데이터를 만들고, 랜섬웨어 모의 침해 여부를 점검하는 자동화 스크립트입니다.

.DESCRIPTION
    스크립트는 먼저 일반영역과 보안영역 폴더 위치, 결과 보고서를 저장할 폴더 위치를 묻습니다.
    이어서 각 영역에 다양한 문서/시스템 형식의 예제 파일을 생성하여 랜섬웨어 감염 전 상태(기준 스냅샷)를 저장합니다.
    RanSim, Atomic Red Team, Caldera 시뮬레이터 설치 여부를 확인하고 필요 시 설치 안내를 제공합니다.
    사용자가 시뮬레이터 실행을 마치면, 최초 스냅샷과 비교하여 변경·삭제·신규 파일을 찾아 침해 징후를 보고합니다.
    결과는 CSV 및 JSON 파일로 저장되며, 모든 과정은 관리자 권한의 PowerShell에서 실행해야 합니다.

.NOTES
    승인된 테스트 환경에서만 실행하세요.
    실제 운영 데이터가 아닌 예제 폴더에서 실험하는 것이 안전합니다.
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

    # 사용자가 입력한 경로가 비어 있지 않고, 실제로 존재하는지 반복 확인합니다.
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
    # 문서 파일과 시스템/환경 파일을 각각 보관할 폴더를 만듭니다.
    $documentDir = Join-Path $TargetPath 'Documents'
    $systemDir   = Join-Path $TargetPath 'System'
    New-Item -ItemType Directory -Path $documentDir,$systemDir -Force | Out-Null

    # 문서 형식 샘플: 워드, 파워포인트, 엑셀, 한글 등 기본 문서 파일을 생성합니다.
    $docExtensions = 'doc','docx','ppt','pptx','xls','xlsx','hwp','hwpx','txt','pdf'
    foreach ($ext in $docExtensions) {
        $filePath = Join-Path $documentDir "${AreaName}_Sample.${ext}"
        if (-not (Test-Path -LiteralPath $filePath)) {
            "${AreaName} 문서 샘플 (${ext}) - $(Get-Date -Format o)" | Set-Content -Path $filePath -Encoding UTF8
        }
    }

    # ZIP 파일은 폴더를 임시로 만들어 압축합니다.
    $zipPath = Join-Path $documentDir "${AreaName}_자료모음.zip"
    if (-not (Test-Path -LiteralPath $zipPath)) {
        $tempZipDir = Join-Path $TargetPath ("TempZip_${AreaName}_" + [guid]::NewGuid().Guid)
        New-Item -ItemType Directory -Path $tempZipDir -Force | Out-Null
        "${AreaName} ZIP 샘플 - $(Get-Date -Format o)" | Set-Content -Path (Join-Path $tempZipDir 'readme.txt') -Encoding UTF8
        Compress-Archive -Path (Join-Path $tempZipDir 'readme.txt') -DestinationPath $zipPath -Force
        Remove-Item -Path $tempZipDir -Recurse -Force
    }

    # PNG/JPG 이미지는 1픽셀짜리 예제 이미지를 Base64로 디코딩하여 만듭니다.
    $pngPath = Join-Path $documentDir "${AreaName}_diagram.png"
    if (-not (Test-Path -LiteralPath $pngPath)) {
        # 줄바꿈을 제거하기 위해 추가 가공이 필요 없도록 Base64 문자열을 한 줄로 정리했습니다.
        $pngBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMBAFdxl3sAAAAASUVORK5CYII='
        $pngBytes = [System.Convert]::FromBase64String($pngBase64)
        [System.IO.File]::WriteAllBytes($pngPath, $pngBytes)
    }

    $jpgPath = Join-Path $documentDir "${AreaName}_photo.jpg"
    if (-not (Test-Path -LiteralPath $jpgPath)) {
        # 아래 Base64는 1x1 픽셀의 단순한 JPEG 이미지입니다.
        $jpgBase64 = '/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////2wBDAf//////////////////////////////////////////////////////////////////////////////////////wAARCAABAAEDAREAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAb/xAAVEQEBAAAAAAAAAAAAAAAAAAAAEf/aAAwDAQACEAMQAAAB7AAAAP/EABQRAQAAAAAAAAAAAAAAAAAAABD/2gAIAQEAAT8AJ//EABQRAQAAAAAAAAAAAAAAAAAAABD/2gAIAQIBAT8AJ//EABQRAQAAAAAAAAAAAAAAAAAAABD/2gAIAQEABj8AJ//Z'
        try {
            $jpgBytes = [System.Convert]::FromBase64String($jpgBase64)
            [System.IO.File]::WriteAllBytes($jpgPath, $jpgBytes)
        }
        catch {
            Write-Warning "JPEG 샘플 이미지를 만드는 중 오류가 발생했습니다: $($_.Exception.Message)"
        }
    }

    # 시스템/환경 설정 샘플: JSON, INI, CSV, CONFIG, REG, DAT 파일을 생성합니다.
    $systemSamples = @(
        @{ Name = 'system_config.json'; Content = @{ Service = 'LineOfBusinessApp'; Version = '1.0.0'; Maintainer = 'SecurityTeam'; Area = $AreaName } | ConvertTo-Json -Depth 3 },
        @{ Name = 'environment.ini'; Content = "[Environment]`nZone=$AreaName`nGenerated=$(Get-Date -Format o)" },
        @{ Name = 'sensitive_list.csv'; Content = "Key,Value`nApiKey,REDACTED-$AreaName`nDatabase,Primary-$AreaName" },
        @{ Name = 'appSettings.config'; Content = "<configuration>\n  <appSettings>\n    <add key='Area' value='$AreaName' />\n    <add key='LastGenerated' value='$(Get-Date -Format o)' />\n  </appSettings>\n</configuration>" },
        @{ Name = 'policies.reg'; Content = @"
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\SampleCompany]
"SecureArea"="$AreaName"
"@
        },
        @{ Name = 'cache.dat'; Content = "SessionId=$(New-Guid)" }
    )
    foreach ($sample in $systemSamples) {
        $path = Join-Path $systemDir $sample.Name
        if (-not (Test-Path -LiteralPath $path)) {
            $encoding = if ($sample.Name -like '*.reg') { 'Unicode' } else { 'UTF8' }
            $sample.Content | Set-Content -Path $path -Encoding $encoding
        }
    }

    # DLL 파일은 간단한 MZ 헤더를 가진 더미 파일로 생성합니다.
    $dllPath = Join-Path $systemDir "${AreaName}_Helper.dll"
    if (-not (Test-Path -LiteralPath $dllPath)) {
        $dllBase64 = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAA'
        [System.IO.File]::WriteAllBytes($dllPath, [System.Convert]::FromBase64String($dllBase64))
    }
}

function Get-AreaSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AreaPath,
        [Parameter(Mandatory)][string]$AreaName
    )

    Write-Verbose "[$AreaName] 파일 무결성 스냅샷을 수집하는 중입니다."
    # 폴더 안 모든 파일을 확인하여 해시(SHA256)와 용량, 수정일을 기록합니다.
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

    # baseline(기준 스냅샷)과 현재 스냅샷을 비교하여 변경/삭제/신규 파일을 나눠 담습니다.
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

    # 설치 여부 확인을 위해 대표적인 실행 파일 위치를 순서대로 확인합니다.
    $candidatePaths = @(
        'C:\\KB4\\Newsim\\Ranstart.exe',
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
    # 최신 RanSim 패키지 다운로드 주소입니다. 필요 시 보안망에서 미리 다운로드해 두세요.
    $downloadUrl = 'https://assets.knowbe4.com/download/ransim/KnowBe4RanSim.zip'
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

    # PowerShell 모듈 Invoke-AtomicRedTeam 설치 여부 확인 후 필요 시 설치합니다.
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

    # 기본 설치 경로(C:\Caldera)가 있는지 확인합니다.
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
        # 현재 상태 스냅샷을 다시 찍어 기준 정보와 비교합니다.
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
# 1단계: 일반영역, 보안영역, 보고서 저장 폴더 경로를 차례대로 입력받습니다.
$generalPath = Read-ValidatedPath -Prompt '일반영역 폴더 경로를 입력하세요' -Type Directory -AllowCreate
$securePath  = Read-ValidatedPath -Prompt '보안영역 폴더 경로를 입력하세요' -Type Directory -AllowCreate
$reportPath  = Read-ValidatedPath -Prompt '결과 데이터를 저장할 폴더 경로를 입력하세요' -Type Directory -AllowCreate

# 2단계: 입력받은 경로 안에 예제 문서/시스템 데이터를 생성합니다.
$areas = @(
    [pscustomobject]@{ Name = 'GeneralArea'; Path = $generalPath },
    [pscustomobject]@{ Name = 'SecureArea';  Path = $securePath }
)

foreach ($area in $areas) {
    Initialize-AreaData -AreaName $area.Name -TargetPath $area.Path
}

# 3단계: 현재 상태를 기준선으로 저장합니다.
$baselines = @{}
foreach ($area in $areas) {
    $baselines[$area.Name] = Get-AreaSnapshot -AreaPath $area.Path -AreaName $area.Name
}

Write-Host '기본 무결성 스냅샷을 완료했습니다. 시뮬레이터 준비 상태를 확인합니다.' -ForegroundColor Cyan
$staging = Join-Path $reportPath "SimulatorPackages_$(Get-Date -Format yyyyMMddHHmmss)"
New-Item -ItemType Directory -Path $staging -Force | Out-Null

# 4단계: RanSim, Atomic Red Team, Caldera가 설치되어 있는지 확인하고 필요 시 설치 안내를 제공합니다.
$ransomExe = Ensure-RanSim -StagingPath $staging
$atomicReady = Ensure-AtomicRedTeam
$calderaPath = Ensure-Caldera -StagingPath $staging

Write-Host '각 시뮬레이터를 통해 랜섬웨어 시나리오를 실행한 뒤 Enter 키를 눌러 계속하세요.' -ForegroundColor Yellow
Write-Host 'RanSim 시나리오 실행 완료 후 Enter: ' -NoNewline
[void][System.Console]::ReadLine()
Write-Host 'Atomic Red Team/Caldera 기반 테스트 실행 완료 후 Enter: ' -NoNewline
[void][System.Console]::ReadLine()

# 5단계: 시뮬레이터 실행 이후 변경된 내용을 분석하여 결과를 정리합니다.
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
