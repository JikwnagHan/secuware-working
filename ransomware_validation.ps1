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

function New-DocumentSelectionPlan {
    [CmdletBinding()]
    param()

    # 확장자별로 무작위 용량을 뽑되 재현성을 위해 하나의 시드를 공유합니다.
    $docExtensions = @('doc','docx','ppt','pptx','xls','xlsx','hwp','hwpx','txt')
    $sizeOptions = @(
        [pscustomobject]@{ Label = 'Small';  Bytes = 64KB },
        [pscustomobject]@{ Label = 'Medium'; Bytes = 256KB },
        [pscustomobject]@{ Label = 'Large';  Bytes = 1MB }
    )

    $seed = Get-Random -Minimum 1000 -Maximum 999999
    $random = [System.Random]::new($seed)

    $files = foreach ($ext in $docExtensions) {
        $choice = $sizeOptions[$random.Next(0, $sizeOptions.Count)]
        [pscustomobject]@{
            Extension  = $ext
            SizeLabel  = $choice.Label
            SizeBytes  = $choice.Bytes
        }
    }

    return [pscustomobject]@{
        Seed  = $seed
        Files = $files
    }
}

function Write-RandomFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][int]$SizeBytes,
        [Parameter()][int]$Seed
    )

    $directory = Split-Path -Path $Path -Parent
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $random = if ($PSBoundParameters.ContainsKey('Seed')) {
        [System.Random]::new($Seed)
    }
    else {
        [System.Random]::new()
    }

    $buffer = New-Object byte[] $SizeBytes
    $random.NextBytes($buffer)
    [System.IO.File]::WriteAllBytes($Path, $buffer)
}

function Export-DocumentSelectionPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Plan,
        [Parameter(Mandatory)][string]$ReportPath
    )

    $timestamp = Get-Date -Format yyyyMMdd_HHmmss
    $csvPath = Join-Path $ReportPath ("DocumentPlan_{0}.csv" -f $timestamp)

    $records = foreach ($entry in $Plan.Files) {
        [pscustomobject]@{
            Seed           = $Plan.Seed
            Extension      = $entry.Extension
            SizeLabel      = $entry.SizeLabel
            SizeBytes      = $entry.SizeBytes
            SizeKilobytes  = [Math]::Round($entry.SizeBytes / 1KB, 2)
        }
    }

    $records | Export-Csv -Path $csvPath -Encoding UTF8 -NoTypeInformation
    return $csvPath
}

function Add-BinaryMarker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Marker
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Marker)
    $stream = $null
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        $stream.Seek(0, [System.IO.SeekOrigin]::End) | Out-Null
        $stream.Write($bytes, 0, $bytes.Length)
    }
    finally {
        if ($stream) { $stream.Dispose() }
    }
}

function Get-RelativePathFromRoot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$FullPath
    )

    try {
        $rootFull = [System.IO.Path]::GetFullPath($Root)
        $pathFull = [System.IO.Path]::GetFullPath($FullPath)
    }
    catch {
        return $null
    }

    if ($pathFull.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $pathFull.Substring($rootFull.Length).TrimStart('\\')
    }

    return $null
}

function Initialize-AreaData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AreaName,
        [Parameter(Mandatory)][string]$TargetPath,
        [Parameter(Mandatory)]$DocumentPlan
    )

    Write-Verbose "[$AreaName] 샘플 데이터를 생성하는 중입니다."

    $documentDir = Join-Path $TargetPath 'Docs'
    $systemDir   = Join-Path $TargetPath 'SysCfg'
    $workspace   = Join-Path $TargetPath '_AssessmentWorkspace'
    $scriptsDir  = Join-Path $workspace 'Scripts'

    New-Item -ItemType Directory -Path $documentDir,$systemDir,$workspace,$scriptsDir -Force | Out-Null

    $docIndex = @{}
    $systemIndex = @{}
    $manifest = New-Object System.Collections.Generic.List[object]

    for ($i = 0; $i -lt $DocumentPlan.Files.Count; $i++) {
        $entry = $DocumentPlan.Files[$i]
        $seed  = $DocumentPlan.Seed + $i
        $fileName = "Doc_{0}.{1}" -f ($entry.Extension.ToUpper()), $entry.Extension
        $filePath = Join-Path $documentDir $fileName
        Write-RandomFile -Path $filePath -SizeBytes $entry.SizeBytes -Seed $seed
        $docIndex[$entry.Extension] = $filePath
        $manifest.Add([pscustomobject]@{
            Category   = 'Docs'
            Extension  = $entry.Extension
            SizeLabel  = $entry.SizeLabel
            SizeBytes  = $entry.SizeBytes
            FilePath   = $filePath
        }) | Out-Null
    }

    $pngPath = Join-Path $documentDir 'DocPreview.png'
    if (-not (Test-Path -LiteralPath $pngPath)) {
        $pngBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMBAFdxl3sAAAAASUVORK5CYII='
        [System.IO.File]::WriteAllBytes($pngPath, [Convert]::FromBase64String($pngBase64))
    }
    $docIndex['png'] = $pngPath
    $manifest.Add([pscustomobject]@{
        Category  = 'Docs'
        Extension = 'png'
        SizeLabel = 'Fixed'
        SizeBytes = (Get-Item $pngPath).Length
        FilePath  = $pngPath
    }) | Out-Null

    $jpgPath = Join-Path $documentDir 'DocPreview.jpg'
    if (-not (Test-Path -LiteralPath $jpgPath)) {
        $jpgBase64 = '/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////2wBDAf//////////////////////////////////////////////////////////////////////////////////////wAARCAABAAEDAREAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAb/xAAVEQEBAAAAAAAAAAAAAAAAAAAAEf/aAAwDAQACEAMQAAAB7AAAAP/EABQRAQAAAAAAAAAAAAAAAAAAABD/2gAIAQEAAT8AJ//EABQRAQAAAAAAAAAAAAAAAAAAABD/2gAIAQIBAT8AJ//EABQRAQAAAAAAAAAAAAAAAAAAABD/2gAIAQEABj8AJ//Z'
        try {
            [System.IO.File]::WriteAllBytes($jpgPath, [Convert]::FromBase64String($jpgBase64))
        }
        catch {
            Write-Warning "JPEG 샘플 이미지를 만드는 중 오류가 발생했습니다: $($_.Exception.Message)"
            Set-Content -Path $jpgPath -Value 'Fallback JPEG sample' -Encoding UTF8
        }
    }
    $docIndex['jpg'] = $jpgPath
    $manifest.Add([pscustomobject]@{
        Category  = 'Docs'
        Extension = 'jpg'
        SizeLabel = 'Fixed'
        SizeBytes = (Get-Item $jpgPath).Length
        FilePath  = $jpgPath
    }) | Out-Null

    $hostsPath = Join-Path $systemDir 'hosts_copy'
    "127.0.0.1`tlocalhost`n# $AreaName sample hosts" | Set-Content -Path $hostsPath -Encoding ASCII
    $systemIndex['hosts'] = $hostsPath
    $manifest.Add([pscustomobject]@{
        Category  = 'SysCfg'
        Extension = 'hosts'
        SizeLabel = 'Fixed'
        SizeBytes = (Get-Item $hostsPath).Length
        FilePath  = $hostsPath
    }) | Out-Null

    $envPath = Join-Path $systemDir 'system.env'
    "AREA=$AreaName`nMODE=Evaluation`nUPDATED=$(Get-Date -Format o)" | Set-Content -Path $envPath -Encoding UTF8
    $systemIndex['env'] = $envPath
    $manifest.Add([pscustomobject]@{
        Category  = 'SysCfg'
        Extension = 'env'
        SizeLabel = 'Fixed'
        SizeBytes = (Get-Item $envPath).Length
        FilePath  = $envPath
    }) | Out-Null

    $jsonPath = Join-Path $systemDir 'appsettings.json'
    @{ Application = 'DataProtectionAssessment'; Area = $AreaName; Generated = (Get-Date -Format o) } | ConvertTo-Json -Depth 3 | Set-Content -Path $jsonPath -Encoding UTF8
    $systemIndex['json'] = $jsonPath
    $manifest.Add([pscustomobject]@{
        Category  = 'SysCfg'
        Extension = 'json'
        SizeLabel = 'Fixed'
        SizeBytes = (Get-Item $jsonPath).Length
        FilePath  = $jsonPath
    }) | Out-Null

    $iniPath = Join-Path $systemDir 'config.ini'
    "[Core]`nRole=$AreaName`nLastGenerated=$(Get-Date -Format o)" | Set-Content -Path $iniPath -Encoding UTF8
    $systemIndex['ini'] = $iniPath
    $manifest.Add([pscustomobject]@{
        Category  = 'SysCfg'
        Extension = 'ini'
        SizeLabel = 'Fixed'
        SizeBytes = (Get-Item $iniPath).Length
        FilePath  = $iniPath
    }) | Out-Null

    $regPath = Join-Path $systemDir 'registry_backup.reg'
    @"
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\SampleCompany]
"SecureArea"="$AreaName"
"LastBaseline"="$(Get-Date -Format o)"
"@ | Set-Content -Path $regPath -Encoding Unicode
    $systemIndex['reg'] = $regPath
    $manifest.Add([pscustomobject]@{
        Category  = 'SysCfg'
        Extension = 'reg'
        SizeLabel = 'Fixed'
        SizeBytes = (Get-Item $regPath).Length
        FilePath  = $regPath
    }) | Out-Null

    $csvPath = Join-Path $systemDir 'system_profile.csv'
    "Key,Value`nArea,$AreaName`nGenerated,$([DateTime]::UtcNow.ToString('o'))" | Set-Content -Path $csvPath -Encoding UTF8
    $systemIndex['csv'] = $csvPath
    $manifest.Add([pscustomobject]@{
        Category  = 'SysCfg'
        Extension = 'csv'
        SizeLabel = 'Fixed'
        SizeBytes = (Get-Item $csvPath).Length
        FilePath  = $csvPath
    }) | Out-Null

    $configPath = Join-Path $systemDir 'appsettings.config'
    "<configuration>`n  <appSettings>`n    <add key='Area' value='$AreaName' />`n    <add key='Baseline' value='$(Get-Date -Format o)' />`n  </appSettings>`n</configuration>" | Set-Content -Path $configPath -Encoding UTF8
    $systemIndex['config'] = $configPath
    $manifest.Add([pscustomobject]@{
        Category  = 'SysCfg'
        Extension = 'config'
        SizeLabel = 'Fixed'
        SizeBytes = (Get-Item $configPath).Length
        FilePath  = $configPath
    }) | Out-Null

    $datPath = Join-Path $systemDir 'cache.dat'
    Write-RandomFile -Path $datPath -SizeBytes 4096 -Seed ($DocumentPlan.Seed + 100)
    $systemIndex['dat'] = $datPath
    $manifest.Add([pscustomobject]@{
        Category  = 'SysCfg'
        Extension = 'dat'
        SizeLabel = 'Fixed'
        SizeBytes = (Get-Item $datPath).Length
        FilePath  = $datPath
    }) | Out-Null

    $dllPath = Join-Path $systemDir 'SupportLibrary.dll'
    if (-not (Test-Path -LiteralPath $dllPath)) {
        $dllBase64 = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        [System.IO.File]::WriteAllBytes($dllPath, [Convert]::FromBase64String($dllBase64))
    }
    $systemIndex['dll'] = $dllPath
    $manifest.Add([pscustomobject]@{
        Category  = 'SysCfg'
        Extension = 'dll'
        SizeLabel = 'Fixed'
        SizeBytes = (Get-Item $dllPath).Length
        FilePath  = $dllPath
    }) | Out-Null

    $operationPaths = [pscustomobject]@{
        DocsArchive        = Join-Path $workspace 'DocsArchive.zip'
        DocsArchiveExtract = Join-Path $workspace 'DocsArchive_Unpacked'
        SysArchive         = Join-Path $workspace 'SysCfgArchive.zip'
        SysArchiveExtract  = Join-Path $workspace 'SysCfgArchive_Unpacked'
        DocBase64          = Join-Path $workspace 'DocPayload.b64'
        DocRestored        = Join-Path $workspace 'DocPayload_Restore.doc'
        PptBase64          = Join-Path $workspace 'PptPayload.b64'
        PptRestored        = Join-Path $workspace 'PptPayload_Restore.ppt'
        ExfilRoot          = Join-Path $workspace 'Exfil'
        ExfilArchive       = Join-Path $workspace 'ExfilBundle.zip'
        ExfilArchiveBase64 = Join-Path $workspace 'ExfilBundle.b64'
        DiscoveryFolder    = Join-Path $workspace 'Discovery'
    }

    New-Item -ItemType Directory -Path $operationPaths.DocsArchiveExtract,$operationPaths.SysArchiveExtract,$operationPaths.ExfilRoot,$operationPaths.DiscoveryFolder -Force | Out-Null

    return [pscustomobject]@{
        DocsPath      = $documentDir
        SysCfgPath    = $systemDir
        WorkspacePath = $workspace
        ScriptsPath   = $scriptsDir
        DocumentIndex = $docIndex
        SystemIndex   = $systemIndex
        OperationPaths= $operationPaths
        Manifest      = $manifest
    }
}

function Measure-DataProtectionBaseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Areas,
        [Parameter(Mandatory)][string]$ReportPath
    )

    Write-Host '입력된 영역의 데이터 보호 기준 상태를 진단합니다.' -ForegroundColor Cyan
    $records = @()

    foreach ($area in $Areas) {
        $documentDir = if ($area.PSObject.Properties.Match('Context').Count -gt 0) { $area.Context.DocsPath } else { Join-Path $area.Path 'Docs' }
        $systemDir   = if ($area.PSObject.Properties.Match('Context').Count -gt 0) { $area.Context.SysCfgPath } else { Join-Path $area.Path 'SysCfg' }

        $docFiles = @(Get-ChildItem -Path $documentDir -File -Recurse -ErrorAction SilentlyContinue)
        $sysFiles = @(Get-ChildItem -Path $systemDir -File -Recurse -ErrorAction SilentlyContinue)

        $docSize = ($docFiles | Measure-Object -Property Length -Sum).Sum
        $sysSize = ($sysFiles | Measure-Object -Property Length -Sum).Sum

        $records += [pscustomobject]@{
            Timestamp                = Get-Date
            AreaName                 = $area.Name
            DocumentFileCount        = $docFiles.Count
            DocumentTotalSizeMB      = if ($docSize) { [Math]::Round($docSize / 1MB, 3) } else { 0 }
            SystemFileCount          = $sysFiles.Count
            SystemTotalSizeMB        = if ($sysSize) { [Math]::Round($sysSize / 1MB, 3) } else { 0 }
            EarliestDocumentWriteUTC = if ($docFiles) { ($docFiles | Sort-Object LastWriteTimeUtc | Select-Object -First 1).LastWriteTimeUtc } else { $null }
            LatestDocumentWriteUTC   = if ($docFiles) { ($docFiles | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1).LastWriteTimeUtc } else { $null }
            EarliestSystemWriteUTC   = if ($sysFiles) { ($sysFiles | Sort-Object LastWriteTimeUtc | Select-Object -First 1).LastWriteTimeUtc } else { $null }
            LatestSystemWriteUTC     = if ($sysFiles) { ($sysFiles | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1).LastWriteTimeUtc } else { $null }
        }

        Write-Host "[$($area.Name)] 문서 ${($docFiles.Count)}건, 시스템 파일 ${($sysFiles.Count)}건을 확인했습니다." -ForegroundColor Green
    }

    $baselineCsv = Join-Path $ReportPath ("DataProtection_Baseline_{0}.csv" -f (Get-Date -Format yyyyMMdd_HHmmss))
    $records | Export-Csv -Path $baselineCsv -Encoding UTF8 -NoTypeInformation
    Write-Host "데이터 보호 기준 측정 결과를 CSV로 저장했습니다: $baselineCsv" -ForegroundColor Green

    return $records
}

function Get-MalwareOperationPlan {
    [CmdletBinding()]
    param()

    $ops = New-Object System.Collections.Generic.List[object]
    $id = 1

    $documentExts = @('doc','docx','ppt','pptx','xls','xlsx','hwp','hwpx','txt')
    foreach ($ext in $documentExts) {
        $ops.Add([pscustomobject]@{
            Id           = $id
            Bucket       = '1.FileModification'
            Technique    = 'T1565.001'
            AtomicTestId = if ($id -eq 1) { 'T1565.001-1' } else { $null }
            ActionType   = 'AppendMarker'
            Description  = ".${ext} 문서에 랜섬웨어 시뮬레이터 표시 문자열 추가"
            Parameters   = @{ Extension = $ext }
        }) | Out-Null
        $id++
    }

    $ops.Add([pscustomobject]@{
        Id           = $id
        Bucket       = '1.FileModification'
        Technique    = 'T1565.001'
        AtomicTestId = $null
        ActionType   = 'AppendSystemMarker'
        Description  = 'system.env 설정 파일에 악성 표시 문자열 추가'
        Parameters   = @{ SystemKey = 'env' }
    }) | Out-Null
    $id++

    $ops.Add([pscustomobject]@{
        Id           = $id
        Bucket       = '2.ArchiveEncoding'
        Technique    = 'T1560.001'
        AtomicTestId = 'T1560.001-1'
        ActionType   = 'Compress'
        Description  = 'Docs 폴더를 ZIP으로 압축'
        Parameters   = @{ Source = 'Docs'; DestinationKey = 'DocsArchive' }
    }) | Out-Null
    $id++

    $ops.Add([pscustomobject]@{
        Id           = $id
        Bucket       = '2.ArchiveEncoding'
        Technique    = 'T1560.001'
        AtomicTestId = $null
        ActionType   = 'Decompress'
        Description  = 'DocsArchive.zip을 임시 폴더에 압축 해제'
        Parameters   = @{ ArchiveKey = 'DocsArchive'; DestinationKey = 'DocsArchiveExtract' }
    }) | Out-Null
    $id++

    $ops.Add([pscustomobject]@{
        Id           = $id
        Bucket       = '2.ArchiveEncoding'
        Technique    = 'T1560.001'
        AtomicTestId = 'T1560.001-2'
        ActionType   = 'Compress'
        Description  = 'SysCfg 폴더를 ZIP으로 압축'
        Parameters   = @{ Source = 'SysCfg'; DestinationKey = 'SysArchive' }
    }) | Out-Null
    $id++

    $ops.Add([pscustomobject]@{
        Id           = $id
        Bucket       = '2.ArchiveEncoding'
        Technique    = 'T1560.001'
        AtomicTestId = $null
        ActionType   = 'Decompress'
        Description  = 'SysCfgArchive.zip을 임시 폴더에 압축 해제'
        Parameters   = @{ ArchiveKey = 'SysArchive'; DestinationKey = 'SysArchiveExtract' }
    }) | Out-Null
    $id++

    $ops.Add([pscustomobject]@{
        Id           = $id
        Bucket       = '2.ArchiveEncoding'
        Technique    = 'T1132.001'
        AtomicTestId = 'T1132.001-1'
        ActionType   = 'Base64Encode'
        Description  = 'DOC 파일을 Base64로 인코딩'
        Parameters   = @{ Extension = 'doc'; OutputKey = 'DocBase64' }
    }) | Out-Null
    $id++

    $ops.Add([pscustomobject]@{
        Id           = $id
        Bucket       = '2.ArchiveEncoding'
        Technique    = 'T1132.001'
        AtomicTestId = 'T1132.001-2'
        ActionType   = 'Base64Decode'
        Description  = 'DOC Base64 파일을 원본으로 복원'
        Parameters   = @{ InputKey = 'DocBase64'; OutputKey = 'DocRestored'; OutputExtension = 'doc' }
    }) | Out-Null
    $id++

    $ops.Add([pscustomobject]@{
        Id           = $id
        Bucket       = '2.ArchiveEncoding'
        Technique    = 'T1132.001'
        AtomicTestId = 'T1132.001-3'
        ActionType   = 'Base64Encode'
        Description  = 'PPT 파일을 Base64로 인코딩'
        Parameters   = @{ Extension = 'ppt'; OutputKey = 'PptBase64' }
    }) | Out-Null
    $id++

    $ops.Add([pscustomobject]@{
        Id           = $id
        Bucket       = '2.ArchiveEncoding'
        Technique    = 'T1132.001'
        AtomicTestId = 'T1132.001-4'
        ActionType   = 'Base64Decode'
        Description  = 'PPT Base64 파일을 원본으로 복원'
        Parameters   = @{ InputKey = 'PptBase64'; OutputKey = 'PptRestored'; OutputExtension = 'ppt' }
    }) | Out-Null
    $id++

    $scriptCopies = @(
        @{ Extension='doc';  Engine='PowerShell'; DestinationName='Doc_script_copy.doc';      Atomic='T1059.003-1' },
        @{ Extension='docx'; Engine='PowerShell'; DestinationName='Docx_script_copy.docx';    Atomic='T1059.003-2' },
        @{ Extension='ppt';  Engine='Cmd';        DestinationName='Ppt_cmd_copy.ppt';         Atomic='T1059.003-3' },
        @{ Extension='pptx'; Engine='Cmd';        DestinationName='Pptx_cmd_copy.pptx';       Atomic='T1059.003-5' },
        @{ Extension='xls';  Engine='PowerShell'; DestinationName='Xls_script_copy.xls';      Atomic='T1059.003-6' },
        @{ Extension='xlsx'; Engine='PowerShell'; DestinationName='Xlsx_script_copy.xlsx';    Atomic='T1059.003-7' },
        @{ Extension='hwp';  Engine='Cmd';        DestinationName='Hwp_cmd_copy.hwp';         Atomic=$null },
        @{ Extension='hwpx'; Engine='Cmd';        DestinationName='Hwpx_cmd_copy.hwpx';       Atomic=$null }
    )
    foreach ($item in $scriptCopies) {
        $ops.Add([pscustomobject]@{
            Id           = $id
            Bucket       = '3.ScriptingManipulation'
            Technique    = 'T1059'
            AtomicTestId = $item.Atomic
            ActionType   = 'SimulateScriptCopy'
            Description  = "스크립트 기반 복사: .$($item.Extension) -> $($item.DestinationName)"
            Parameters   = $item
        }) | Out-Null
        $id++
    }

    $permissionOps = @(
        @{ Extension='doc'; Attributes=@('Hidden','ReadOnly'); Technique='T1222.001'; Atomic='T1222.001-1'; Description='DOC 파일 속성을 숨김+읽기 전용으로 변경' },
        @{ Extension='doc'; Attributes=@('Normal');           Technique='T1222.001'; Atomic='T1222.001-2'; Description='DOC 파일 속성을 Normal로 복구' },
        @{ Extension='png'; Attributes=@('Hidden');           Technique='T1564.001'; Atomic='T1564.001-1'; Description='PNG 파일 숨김 처리' },
        @{ Extension='png'; Attributes=@('Normal');           Technique='T1564.001'; Atomic='T1564.001-2'; Description='PNG 파일 숨김 해제' },
        @{ Extension='doc'; DaysOffset=-2;                    Technique='T1099';     Atomic='T1099-1';      Description='DOC 파일의 수정 시간을 과거로 변경'; Action='TouchTimestamp' },
        @{ Extension='doc'; Rule='Users:(R)';                 Technique='T1222.001'; Atomic='T1222.001-3'; Description='DOC 파일 ACL을 Users:(R)으로 조정'; Action='InvokeIcacls' }
    )

    foreach ($item in $permissionOps) {
        $actionType = if ($item.Action) { $item.Action } else { 'SetAttributes' }
        $parameters = $item.Clone()
        $parameters.Remove('Technique')
        $parameters.Remove('Atomic')
        if ($parameters.ContainsKey('Description')) { $parameters.Remove('Description') }
        if ($parameters.ContainsKey('Action')) { $parameters.Remove('Action') }
        $ops.Add([pscustomobject]@{
            Id           = $id
            Bucket       = '4.PermissionAttribute'
            Technique    = $item.Technique
            AtomicTestId = $item.Atomic
            ActionType   = $actionType
            Description  = $item.Description
            Parameters   = $parameters
        }) | Out-Null
        $id++
    }

    $cleanupTargets = @(
        @{ Target='Docs'; FileName='Doc_script_copy.doc';   PathType='File';      Atomic='T1070-1' },
        @{ Target='Docs'; FileName='Docx_script_copy.docx'; PathType='File';      Atomic='T1070-2' },
        @{ OperationKey='DocsArchiveExtract'; PathType='Directory'; Atomic='T1070-3' },
        @{ OperationKey='SysArchiveExtract';  PathType='Directory'; Atomic='T1070-4' }
    )
    foreach ($item in $cleanupTargets) {
        $ops.Add([pscustomobject]@{
            Id           = $id
            Bucket       = '5.CleanupLike'
            Technique    = 'T1070'
            AtomicTestId = $item.Atomic
            ActionType   = 'RemovePath'
            Description  = '테스트 산출물 정리 작업'
            Parameters   = $item
        }) | Out-Null
        $id++
    }

    $ops.Add([pscustomobject]@{
        Id           = $id
        Bucket       = '5.CleanupLike'
        Technique    = 'T1070'
        AtomicTestId = 'T1070-5'
        ActionType   = 'ClearFile'
        Description  = 'DOC Base64 임시 파일 비우기'
        Parameters   = @{ OperationKey = 'DocBase64' }
    }) | Out-Null
    $id++

    $discoveryOps = @(
        @{ Target='Docs';  OutputName='Discovery_docs.csv';         Technique='T1083';  Atomic='T1083-1'; Action='ListFiles' },
        @{ Target='SysCfg'; OutputName='Discovery_sys.csv';         Technique='T1083';  Atomic='T1083-2'; Action='ListFiles' },
        @{ Target='Docs';  OutputName='Discovery_docs_hashes.csv';  Technique='T1083';  Atomic='T1083-3'; Action='RecordHashes' },
        @{ Target='SysCfg'; OutputName='Discovery_sys_hashes.csv';  Technique='T1083';  Atomic='T1083-4'; Action='RecordHashes' },
        @{ Extension='doc'; OutputName='Discovery_doc_acl.txt';     Technique='T1069';  Atomic='T1069-1'; Action='GetAclReport' }
    )

    foreach ($item in $discoveryOps) {
        $action = $item.Action
        $parameters = $item.Clone()
        $parameters.Remove('Technique')
        $parameters.Remove('Atomic')
        $parameters.Remove('Action')
        $ops.Add([pscustomobject]@{
            Id           = $id
            Bucket       = '6.Discovery'
            Technique    = $item.Technique
            AtomicTestId = $item.Atomic
            ActionType   = $action
            Description  = '발견/열거 시도'
            Parameters   = $parameters
        }) | Out-Null
        $id++
    }

    $exfilOps = @(
        @{ Action='EnsureDirectory';            Technique='T1041';   Atomic='T1041-1'; Parameters=@{ OperationKey='ExfilRoot' };                         Description='Exfil 전용 작업 폴더 보장' },
        @{ Action='CopyToExfil';                Technique='T1041';   Atomic='T1041-2'; Parameters=@{ SourceType='Document'; Extension='doc';  DestinationName='Doc_payload_copy.doc' }; Description='DOC 파일을 Exfil 폴더로 복사' },
        @{ Action='CopyToExfil';                Technique='T1041';   Atomic='T1041-3'; Parameters=@{ SourceType='Document'; Extension='docx'; DestinationName='Docx_payload_copy.docx' }; Description='DOCX 파일을 Exfil 폴더로 복사' },
        @{ Action='CopyOperationFileToExfil';   Technique='T1041';   Atomic='T1041-4'; Parameters=@{ SourceKey='DocsArchive'; DestinationName='DocsArchive_copy.zip' };                 Description='DocsArchive.zip을 Exfil 폴더로 복사' },
        @{ Action='CopySystemToExfil';          Technique='T1041';   Atomic='T1041-5'; Parameters=@{ SystemKey='json'; DestinationName='appsettings_copy.json' };                       Description='appsettings.json 설정 파일을 Exfil 폴더로 복사' },
        @{ Action='ArchiveExfil';               Technique='T1560.001';Atomic='T1560.001-3'; Parameters=@{};                                                                  Description='Exfil 폴더를 ZIP으로 압축' },
        @{ Action='Base64EncodeExfil';          Technique='T1132.001';Atomic='T1132.001-5'; Parameters=@{};                                                                 Description='Exfil ZIP을 Base64로 인코딩' },
        @{ Action='WriteManifest';              Technique='T1041';   Atomic='T1041-6'; Parameters=@{};                                                                     Description='Exfil 결과 요약 manifest 작성' }
    )

    foreach ($item in $exfilOps) {
        $ops.Add([pscustomobject]@{
            Id           = $id
            Bucket       = '7.ExfiltrationPrep'
            Technique    = $item.Technique
            AtomicTestId = $item.Atomic
            ActionType   = $item.Action
            Description  = $item.Description
            Parameters   = $item.Parameters
        }) | Out-Null
        $id++
    }

    return $ops
}

function Invoke-MalwareOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Operation,
        [Parameter(Mandatory)]$Context
    )

    $result = [pscustomobject]@{
        Success       = $true
        Message       = '완료'
        AffectedPaths = @()
    }

    try {
        switch ($Operation.ActionType) {
            'AppendMarker' {
                $ext = $Operation.Parameters.Extension
                if (-not $Context.DocumentIndex.ContainsKey($ext)) { throw "확장자 .$ext 파일을 찾을 수 없습니다." }
                $path = $Context.DocumentIndex[$ext]
                $marker = "`n#AtomicSim-$($Context.AreaName)-$ext $(Get-Date -Format o)"
                Add-BinaryMarker -Path $path -Marker $marker
                $result.AffectedPaths = @($path)
                $result.Message = 'Marker appended'
            }
            'AppendSystemMarker' {
                $key = $Operation.Parameters.SystemKey
                if (-not $Context.SystemIndex.ContainsKey($key)) { throw "시스템 키 '$key' 파일을 찾을 수 없습니다." }
                $path = $Context.SystemIndex[$key]
                $marker = "`n#AtomicSim-$($Context.AreaName)-$key $(Get-Date -Format o)"
                Add-BinaryMarker -Path $path -Marker $marker
                $result.AffectedPaths = @($path)
                $result.Message = 'System marker appended'
            }
            'SetAttributes' {
                $ext = $Operation.Parameters.Extension
                if (-not $Context.DocumentIndex.ContainsKey($ext)) { throw "속성을 변경할 .$ext 파일이 없습니다." }
                $path = $Context.DocumentIndex[$ext]
                $attrs = @()
                if ($Operation.Parameters.ContainsKey('Attributes')) { $attrs = $Operation.Parameters.Attributes }
                if (-not $attrs -or ($attrs -contains 'Normal' -and $attrs.Count -eq 1)) {
                    [System.IO.File]::SetAttributes($path, [System.IO.FileAttributes]::Normal)
                    $result.Message = 'Attributes set to Normal'
                }
                else {
                    $value = [System.IO.FileAttributes]0
                    foreach ($attr in $attrs) {
                        $value = $value -bor [System.Enum]::Parse([System.IO.FileAttributes], $attr, $true)
                    }
                    [System.IO.File]::SetAttributes($path, $value)
                    $result.Message = "Attributes set: $($attrs -join ',')"
                }
                $result.AffectedPaths = @($path)
            }
            'Compress' {
                $source = switch ($Operation.Parameters.Source) {
                    'Docs'   { $Context.DocsPath }
                    'SysCfg' { $Context.SysCfgPath }
                    default  { throw "지원되지 않는 Source: $($Operation.Parameters.Source)" }
                }
                $destinationKey = $Operation.Parameters.DestinationKey
                $destination = $Context.OperationPaths.$destinationKey
                if (Test-Path -LiteralPath $destination) { Remove-Item -LiteralPath $destination -Force }
                Compress-Archive -Path (Join-Path $source '*') -DestinationPath $destination -Force
                $result.AffectedPaths = @($destination)
                $result.Message = "Archive created: $destination"
            }
            'Decompress' {
                $archiveKey = $Operation.Parameters.ArchiveKey
                $archive = $Context.OperationPaths.$archiveKey
                $destKey = $Operation.Parameters.DestinationKey
                $dest = $Context.OperationPaths.$destKey
                if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
                New-Item -ItemType Directory -Path $dest -Force | Out-Null
                Expand-Archive -Path $archive -DestinationPath $dest -Force
                $result.AffectedPaths = @($dest)
                $result.Message = "Archive expanded: $archive"
            }
            'Base64Encode' {
                $source = if ($Operation.Parameters.ContainsKey('Extension')) {
                    $Context.DocumentIndex[$Operation.Parameters.Extension]
                } else {
                    $Context.OperationPaths.$($Operation.Parameters.SourceKey)
                }
                $output = $Context.OperationPaths.$($Operation.Parameters.OutputKey)
                $bytes = [System.IO.File]::ReadAllBytes($source)
                $base64 = [Convert]::ToBase64String($bytes)
                Set-Content -Path $output -Value $base64 -Encoding ASCII
                $result.AffectedPaths = @($output)
                $result.Message = "Base64 written: $output"
            }
            'Base64Decode' {
                $inputPath = $Context.OperationPaths.$($Operation.Parameters.InputKey)
                $output = $Context.OperationPaths.$($Operation.Parameters.OutputKey)
                $base64 = Get-Content -Path $inputPath -Raw
                $bytes = [Convert]::FromBase64String($base64)
                [System.IO.File]::WriteAllBytes($output, $bytes)
                $result.AffectedPaths = @($output)
                $result.Message = "Base64 decoded: $output"
            }
            'SimulateScriptCopy' {
                $ext = $Operation.Parameters.Extension
                if (-not $Context.DocumentIndex.ContainsKey($ext)) { throw "복사 대상 .$ext 파일이 없습니다." }
                $source = $Context.DocumentIndex[$ext]
                $destination = Join-Path $Context.DocsPath $Operation.Parameters.DestinationName
                $engine = $Operation.Parameters.Engine
                $scriptExtension = if ($engine -eq 'PowerShell') { 'ps1' } else { 'bat' }
                $scriptFileName = "op{0}_{1}.{2}" -f $Operation.Id, $ext, $scriptExtension
                $scriptPath = Join-Path $Context.ScriptsPath $scriptFileName

                if ($engine -eq 'PowerShell') {
                    "Copy-Item -Path `"$source`" -Destination `"$destination`" -Force" | Set-Content -Path $scriptPath -Encoding UTF8
                    $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$scriptPath) -Wait -PassThru
                }
                else {
                    "@echo off`ncopy /y `"$source`" `"$destination`"" | Set-Content -Path $scriptPath -Encoding ASCII
                    $proc = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/c',"`"$scriptPath`"") -Wait -PassThru
                }
                if ($proc.ExitCode -ne 0) { throw "스크립트 실행 실패 (ExitCode=$($proc.ExitCode))" }
                $result.AffectedPaths = @($destination)
                $result.Message = 'Script copy executed'
            }
            'TouchTimestamp' {
                $ext = $Operation.Parameters.Extension
                if (-not $Context.DocumentIndex.ContainsKey($ext)) { throw "시간 변경 대상 .$ext 파일이 없습니다." }
                $path = $Context.DocumentIndex[$ext]
                $offset = if ($Operation.Parameters.ContainsKey('DaysOffset')) { [int]$Operation.Parameters.DaysOffset } else { -1 }
                $newTime = (Get-Date).AddDays($offset)
                (Get-Item -LiteralPath $path).LastWriteTime = $newTime
                $result.AffectedPaths = @($path)
                $result.Message = "Timestamp updated to $newTime"
            }
            'InvokeIcacls' {
                $ext = $Operation.Parameters.Extension
                if (-not $Context.DocumentIndex.ContainsKey($ext)) { throw "ACL 변경 대상 .$ext 파일이 없습니다." }
                $path = $Context.DocumentIndex[$ext]
                $rule = if ($Operation.Parameters.Rule) { $Operation.Parameters.Rule } else { 'Users:(R)' }
                $args = "`"$path`" /grant:r $rule"
                $proc = Start-Process -FilePath 'icacls.exe' -ArgumentList $args -Wait -PassThru
                if ($proc.ExitCode -ne 0) { throw "icacls 실패 (ExitCode=$($proc.ExitCode))" }
                $result.AffectedPaths = @($path)
                $result.Message = "icacls applied: $rule"
            }
            'RemovePath' {
                $targetPath = $null
                if ($Operation.Parameters.ContainsKey('OperationKey')) {
                    $targetPath = $Context.OperationPaths.$($Operation.Parameters.OperationKey)
                }
                elseif ($Operation.Parameters.Target -eq 'Docs') {
                    $targetPath = Join-Path $Context.DocsPath $Operation.Parameters.FileName
                }
                elseif ($Operation.Parameters.Target -eq 'Workspace') {
                    $targetPath = Join-Path $Context.WorkspacePath $Operation.Parameters.FileName
                }
                if ($targetPath -and (Test-Path -LiteralPath $targetPath)) {
                    $pathType = $Operation.Parameters.PathType
                    Remove-Item -LiteralPath $targetPath -Force -Recurse
                    if ($pathType -eq 'Directory') { New-Item -ItemType Directory -Path $targetPath -Force | Out-Null }
                    $result.AffectedPaths = @($targetPath)
                    $result.Message = 'Cleanup executed'
                }
                else {
                    $result.Message = 'Cleanup target not found'
                }
            }
            'ClearFile' {
                $path = $Context.OperationPaths.$($Operation.Parameters.OperationKey)
                Set-Content -Path $path -Value '' -Encoding ASCII
                $result.AffectedPaths = @($path)
                $result.Message = 'File cleared'
            }
            'ListFiles' {
                $target = if ($Operation.Parameters.Target -eq 'Docs') { $Context.DocsPath } else { $Context.SysCfgPath }
                $output = Join-Path $Context.OperationPaths.DiscoveryFolder $Operation.Parameters.OutputName
                $rows = Get-ChildItem -LiteralPath $target -File -Recurse | Select-Object Name,FullName,Length,LastWriteTimeUtc,Extension
                $rows | Export-Csv -Path $output -Encoding UTF8 -NoTypeInformation
                $result.AffectedPaths = @($output)
                $result.Message = 'Listing captured'
            }
            'RecordHashes' {
                $target = if ($Operation.Parameters.Target -eq 'Docs') { $Context.DocsPath } else { $Context.SysCfgPath }
                $output = Join-Path $Context.OperationPaths.DiscoveryFolder $Operation.Parameters.OutputName
                $rows = foreach ($file in Get-ChildItem -LiteralPath $target -File -Recurse) {
                    $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256
                    [pscustomobject]@{
                        Name             = $file.Name
                        FullName         = $file.FullName
                        Hash             = $hash.Hash
                        Length           = $file.Length
                        LastWriteTimeUtc = $file.LastWriteTimeUtc
                    }
                }
                $rows | Export-Csv -Path $output -Encoding UTF8 -NoTypeInformation
                $result.AffectedPaths = @($output)
                $result.Message = 'Hashes recorded'
            }
            'GetAclReport' {
                $ext = $Operation.Parameters.Extension
                $path = $Context.DocumentIndex[$ext]
                $output = Join-Path $Context.OperationPaths.DiscoveryFolder $Operation.Parameters.OutputName
                $aclText = (Get-Acl -Path $path | Format-List | Out-String)
                Set-Content -Path $output -Value $aclText -Encoding UTF8
                $result.AffectedPaths = @($output)
                $result.Message = 'ACL report saved'
            }
            'EnsureDirectory' {
                $path = $Context.OperationPaths.$($Operation.Parameters.OperationKey)
                New-Item -ItemType Directory -Path $path -Force | Out-Null
                $result.AffectedPaths = @($path)
                $result.Message = 'Directory ensured'
            }
            'CopyToExfil' {
                $dest = Join-Path $Context.OperationPaths.ExfilRoot $Operation.Parameters.DestinationName
                if ($Operation.Parameters.SourceType -eq 'Document') {
                    $source = $Context.DocumentIndex[$Operation.Parameters.Extension]
                }
                else {
                    throw '지원되지 않는 SourceType'
                }
                Copy-Item -LiteralPath $source -Destination $dest -Force
                $result.AffectedPaths = @($dest)
                $result.Message = 'Document copied to exfil'
            }
            'CopyOperationFileToExfil' {
                $source = $Context.OperationPaths.$($Operation.Parameters.SourceKey)
                $dest = Join-Path $Context.OperationPaths.ExfilRoot $Operation.Parameters.DestinationName
                Copy-Item -LiteralPath $source -Destination $dest -Force
                $result.AffectedPaths = @($dest)
                $result.Message = 'Archive copied to exfil'
            }
            'CopySystemToExfil' {
                $source = $Context.SystemIndex.$($Operation.Parameters.SystemKey)
                $dest = Join-Path $Context.OperationPaths.ExfilRoot $Operation.Parameters.DestinationName
                Copy-Item -LiteralPath $source -Destination $dest -Force
                $result.AffectedPaths = @($dest)
                $result.Message = 'System file copied to exfil'
            }
            'ArchiveExfil' {
                $archive = $Context.OperationPaths.ExfilArchive
                if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
                $items = Get-ChildItem -LiteralPath $Context.OperationPaths.ExfilRoot -File -Recurse
                if ($items) {
                    Compress-Archive -Path (Join-Path $Context.OperationPaths.ExfilRoot '*') -DestinationPath $archive -Force
                    $result.Message = 'Exfil archive created'
                }
                else {
                    [System.IO.File]::WriteAllBytes($archive, [byte[]]@())
                    $result.Message = 'Exfil archive placeholder created (no files)'
                }
                $result.AffectedPaths = @($archive)
            }
            'Base64EncodeExfil' {
                $archive = $Context.OperationPaths.ExfilArchive
                $output = $Context.OperationPaths.ExfilArchiveBase64
                if (-not (Test-Path -LiteralPath $archive)) { throw 'Exfil archive 파일이 존재하지 않습니다.' }
                $bytes = [System.IO.File]::ReadAllBytes($archive)
                $base64 = [Convert]::ToBase64String($bytes)
                Set-Content -Path $output -Value $base64 -Encoding ASCII
                $result.AffectedPaths = @($output)
                $result.Message = 'Exfil archive encoded'
            }
            'WriteManifest' {
                $manifestPath = Join-Path $Context.OperationPaths.ExfilRoot 'manifest.txt'
                $lines = @(
                    "Area=$($Context.AreaName)",
                    "Generated=$(Get-Date -Format o)",
                    'Files:'
                )
                foreach ($item in Get-ChildItem -LiteralPath $Context.OperationPaths.ExfilRoot -File) {
                    $lines += " - $($item.Name) ($($item.Length) bytes)"
                }
                Set-Content -Path $manifestPath -Value $lines -Encoding UTF8
                $result.AffectedPaths = @($manifestPath)
                $result.Message = 'Manifest written'
            }
            default {
                throw "알 수 없는 ActionType: $($Operation.ActionType)"
            }
        }
    }
    catch {
        $result.Success = $false
        $result.Message = $_.Exception.Message
    }

    return $result
}

function Resolve-AtomicsFolder {
    [CmdletBinding()]
    param(
        [Parameter()][string[]]$PreferredPaths
    )

    # 가능한 후보 경로를 우선순위대로 모아서 순차적으로 검사합니다.
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $queue = New-Object 'System.Collections.Generic.List[string]'

    $addCandidate = {
        param($value)
        if ([string]::IsNullOrWhiteSpace($value)) { return }
        try {
            $normalized = [System.IO.Path]::GetFullPath($value)
        }
        catch {
            return
        }
        if ($seen.Add($normalized)) {
            [void]$queue.Add($normalized)
        }
    }

    foreach ($path in $PreferredPaths) { & $addCandidate.Invoke($path) }

    if ($env:ATOMIC_RED_TEAM_PATH) {
        & $addCandidate.Invoke($env:ATOMIC_RED_TEAM_PATH)
    }

    $defaultRoots = @('C:\\AtomicRedTeam', 'D:\\AtomicRedTeam')
    foreach ($root in $defaultRoots) {
        & $addCandidate.Invoke((Join-Path $root 'atomic-red-team-master\\atomics'))
        & $addCandidate.Invoke((Join-Path $root 'atomic-red-team\\atomics'))
        & $addCandidate.Invoke((Join-Path $root 'atomics'))
    }

    & $addCandidate.Invoke('C:\\AtomicRedTeam\\atomic-red-team-master\\atomics')
    & $addCandidate.Invoke('C:\\AtomicRedTeam\\atomics')
    & $addCandidate.Invoke((Join-Path $env:ProgramData 'AtomicRedTeam\\atomics'))
    & $addCandidate.Invoke((Join-Path $env:ProgramFiles 'AtomicRedTeam\\atomics'))

    $modules = Get-Module -ListAvailable -Name Invoke-AtomicRedTeam
    foreach ($module in $modules) {
        $moduleBase = $module.ModuleBase
        if (-not [string]::IsNullOrWhiteSpace($moduleBase)) {
            & $addCandidate.Invoke((Join-Path $moduleBase 'atomics'))
            & $addCandidate.Invoke((Join-Path $moduleBase 'atomic-red-team-master\\atomics'))
            $parent = Split-Path -Path $moduleBase -Parent
            if ($parent) {
                & $addCandidate.Invoke((Join-Path $parent 'atomics'))
                & $addCandidate.Invoke((Join-Path $parent 'atomic-red-team\\atomics'))
                & $addCandidate.Invoke((Join-Path $parent 'atomic-red-team-master\\atomics'))
            }
        }
    }

    foreach ($candidate in $queue) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    return $null
}

function Invoke-MalwareAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$AtomicContext,
        [Parameter(Mandatory)]$Areas,
        [Parameter(Mandatory)][string]$ReportPath,
        [Parameter(Mandatory)]$Baselines
    )

    $timestamp = Get-Date -Format yyyyMMdd_HHmmss
    $operationCsv = Join-Path $ReportPath ("Malware_Performance_Assessment_{0}.csv" -f $timestamp)
    $summaryCsv   = Join-Path $ReportPath ("Malware_Assessment_Summary_{0}.csv" -f $timestamp)
    $fileCsv      = Join-Path $ReportPath ("Malware_Assessment_FileStatus_{0}.csv" -f $timestamp)
    $finalCsv     = Join-Path $ReportPath ("Malware_Assessment_FinalState_{0}.csv" -f $timestamp)
    $logPath      = Join-Path $ReportPath ("Malware_Assessment_Log_{0}.txt" -f $timestamp)

    $plan = Get-MalwareOperationPlan
    $atomicReady = $false
    $atomicsPath = $null
    if ($null -ne $AtomicContext) {
        if ($AtomicContext.PSObject.Properties.Match('Ready').Count -gt 0) {
            $atomicReady = [bool]$AtomicContext.Ready
        }
        elseif ($AtomicContext -is [bool]) {
            $atomicReady = [bool]$AtomicContext
        }

        if ($AtomicContext.PSObject.Properties.Match('AtomicsPath').Count -gt 0) {
            $atomicsPath = $AtomicContext.AtomicsPath
        }
    }

    if ($atomicReady -and -not $atomicsPath) {
        $atomicsPath = Resolve-AtomicsFolder
    }

    $moduleStatus = if ($atomicReady) { 'Invoke-AtomicRedTeam available' } else { 'Module missing - local plan executed' }
    "[Start] $(Get-Date -Format o) 악성코드 성능 검증을 시작합니다. Atomic 모듈 상태: $moduleStatus" | Out-File -FilePath $logPath -Encoding UTF8
    if ($atomicReady -and $atomicsPath) {
        "Invoke-AtomicRedTeam atomics 폴더 확인: $atomicsPath" | Out-File -FilePath $logPath -Append -Encoding UTF8
    }
    elseif ($atomicReady -and -not $atomicsPath) {
        "Invoke-AtomicRedTeam 모듈은 있으나 atomics 폴더를 찾지 못했습니다. GitHub에서 atomic-red-team 저장소를 내려받아 ATOMIC_RED_TEAM_PATH 환경 변수 또는 C:\\AtomicRedTeam 경로에 배치하세요." | Out-File -FilePath $logPath -Append -Encoding UTF8
    }

    $operationEntries = New-Object System.Collections.Generic.List[object]
    $summaryEntries   = New-Object System.Collections.Generic.List[object]
    $fileEntries      = New-Object System.Collections.Generic.List[object]
    $finalStateEntries= New-Object System.Collections.Generic.List[object]
    $areaImpact       = @{}

    foreach ($area in $Areas) {
        if ($area.PSObject.Properties.Match('Context').Count -eq 0) { continue }
        $context = $area.Context
        $context | Add-Member -NotePropertyName AreaName -NotePropertyValue $area.Name -Force
        "[$($area.Name)] 시뮬레이션을 실행합니다." | Out-File -FilePath $logPath -Append -Encoding UTF8

        $areaEntries = New-Object System.Collections.Generic.List[object]
        $impactList  = New-Object System.Collections.Generic.List[object]
        $lastSnapshot = Get-AreaSnapshot -AreaPath $area.Path -AreaName $area.Name

        foreach ($operation in $plan) {
            $atomicOutcome = 'Skipped'
            if ($atomicReady -and $atomicsPath -and $operation.PSObject.Properties.Match('AtomicTestId').Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($operation.AtomicTestId)) {
                try {
                    $parts = $operation.AtomicTestId -split '-'
                    $technique = $parts[0]
                    $testNumber = if ($parts.Count -gt 1) { $parts[1] } else { $null }
                    if ($testNumber) {
                        Invoke-AtomicTest $technique -TestNumbers $testNumber -PathToAtomicsFolder $atomicsPath -Force -ErrorAction Stop | Out-Null
                    }
                    else {
                        Invoke-AtomicTest $technique -PathToAtomicsFolder $atomicsPath -Force -ErrorAction Stop | Out-Null
                    }
                    $atomicOutcome = 'Executed'
                }
                catch {
                    $atomicOutcome = "Failed: $($_.Exception.Message)"
                    "[$($area.Name)] Atomic 실행 실패 ($($operation.AtomicTestId)): $($_.Exception.Message)" | Out-File -FilePath $logPath -Append -Encoding UTF8
                }
            }

            $preSnapshot = $lastSnapshot
            $result = Invoke-MalwareOperation -Operation $operation -Context $context
            $postSnapshot = Get-AreaSnapshot -AreaPath $area.Path -AreaName $area.Name
            $lastSnapshot = $postSnapshot
            $affected = if ($result.AffectedPaths) { $result.AffectedPaths } else { @() }
            $opTimestamp = Get-Date
            $testIdentifier = if ($operation.PSObject.Properties.Match('AtomicTestId').Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($operation.AtomicTestId)) { $operation.AtomicTestId }
                              elseif (-not [string]::IsNullOrWhiteSpace($operation.Technique)) { $operation.Technique }
                              else { "Op-$($operation.Id)" }
            $resultLabel = if ($result.Success) { 'Success' } elseif ($atomicOutcome -eq 'Skipped') { 'Skipped' } else { 'Failed' }
            $messageText = if (-not [string]::IsNullOrWhiteSpace($result.Message)) { $result.Message }
                           elseif (-not [string]::IsNullOrWhiteSpace($atomicOutcome)) { $atomicOutcome }
                           else { 'No additional details.' }

            $preKeys = if ($preSnapshot) { @($preSnapshot.Keys) } else { @() }
            $postKeys = if ($postSnapshot) { @($postSnapshot.Keys) } else { @() }
            $allKeys = @((@($preKeys) + @($postKeys)) | Sort-Object -Unique)
            foreach ($relative in $allKeys) {
                $before = if ($preSnapshot -and $preSnapshot.ContainsKey($relative)) { $preSnapshot[$relative] } else { $null }
                $after  = if ($postSnapshot -and $postSnapshot.ContainsKey($relative)) { $postSnapshot[$relative] } else { $null }
                $fullPath = if ($after) { $after.Path }
                             elseif ($before) { $before.Path }
                             else { Join-Path $area.Path $relative }
                $existsBefore = $null -ne $before
                $existsAfter  = $null -ne $after
                $sizeBefore   = if ($before) { $before.Length } else { 0 }
                $sizeAfter    = if ($after) { $after.Length } else { 0 }
                $hashBefore   = if ($before) { $before.Hash } else { $null }
                $hashAfter    = if ($after) { $after.Hash } else { $null }
                $changed      = ($existsBefore -and -not $existsAfter) -or (-not $existsBefore -and $existsAfter) -or ($existsBefore -and $existsAfter -and $hashBefore -ne $hashAfter)

                $fileEntries.Add([pscustomobject]@{
                    Timestamp      = $opTimestamp
                    Area           = $area.Name
                    FilePath       = $fullPath
                    Exists_Before  = $existsBefore
                    Size_Before    = $sizeBefore
                    SHA256_Before  = $hashBefore
                    Exists_After   = $existsAfter
                    Size_After     = $sizeAfter
                    SHA256_After   = $hashAfter
                    Changed        = $changed
                    Test           = $testIdentifier
                    Result         = $resultLabel
                    Message        = $messageText
                }) | Out-Null
            }

            $entry = [pscustomobject]@{
                Timestamp      = $opTimestamp
                AreaName       = $area.Name
                OperationId    = $operation.Id
                Bucket         = $operation.Bucket
                Technique      = $operation.Technique
                AtomicTestId   = if ($operation.PSObject.Properties.Match('AtomicTestId').Count -gt 0) { $operation.AtomicTestId } else { $null }
                ActionType     = $operation.ActionType
                Description    = $operation.Description
                ModuleStatus   = $moduleStatus
                AtomicExecution= $atomicOutcome
                Success        = $result.Success
                Message        = $result.Message
                AffectedPaths  = ($affected -join '; ')
            }

            $operationEntries.Add($entry)
            $areaEntries.Add($entry)
            $impactList.Add([pscustomobject]@{
                OperationId = $operation.Id
                Bucket      = $operation.Bucket
                Paths       = $affected
                Success     = $result.Success
            }) | Out-Null

            $logLine = "[$($area.Name)] #$($operation.Id) $($operation.ActionType) => $(if ($result.Success) { 'OK' } else { 'FAIL' }) : $($result.Message)"
            $logLine | Out-File -FilePath $logPath -Append -Encoding UTF8
        }

        $areaImpact[$area.Name] = $impactList

        $currentSnapshot = $lastSnapshot
        $comparison = Compare-AreaSnapshots -Baseline $Baselines[$area.Name] -Current $currentSnapshot -AreaName $area.Name

        foreach ($record in $comparison.FileRecords) {
            $finalStateEntries.Add([pscustomobject]@{
                Timestamp    = Get-Date
                AreaName     = $area.Name
                RelativePath = $record.RelativePath
                Status       = $record.Status
                BaselineHash = $record.BaselineHash
                CurrentHash  = $record.CurrentHash
                Note         = $record.Note
            }) | Out-Null
        }

        $relativeStatus = @{}
        foreach ($record in $comparison.FileRecords) {
            $relativeStatus[$record.RelativePath] = $record.Status
        }

        $writeOps = @($impactList | Where-Object { $_.Bucket -eq '1.FileModification' })
        $writeAttempts = $writeOps.Count
        $writeBlocked  = 0
        foreach ($impact in $writeOps) {
            foreach ($path in $impact.Paths) {
                $relative = Get-RelativePathFromRoot -Root $area.Path -FullPath $path
                if ($null -ne $relative -and $relativeStatus.ContainsKey($relative) -and $relativeStatus[$relative] -eq 'Intact') {
                    $writeBlocked++
                }
            }
        }
        $writeBlockRate = if ($writeAttempts -gt 0) { [Math]::Round(($writeBlocked / $writeAttempts) * 100, 2) } else { 0 }

        $archiveOps = @($impactList | Where-Object { $_.Bucket -eq '2.ArchiveEncoding' })
        $archiveAttempts = $archiveOps.Count
        $archiveNeutral = 0
        foreach ($impact in $archiveOps) {
            $changed = $false
            foreach ($path in $impact.Paths) {
                $relative = Get-RelativePathFromRoot -Root $area.Path -FullPath $path
                if ($null -ne $relative -and $relativeStatus.ContainsKey($relative) -and $relativeStatus[$relative] -ne 'Intact') {
                    $changed = $true
                    break
                }
            }
            if (-not $changed -and $comparison.ModifiedCount -eq 0) { $archiveNeutral++ }
            elseif (-not $changed -and $impact.Paths.Count -gt 0) { $archiveNeutral++ }
        }
        $archiveRate = if ($archiveAttempts -gt 0) { [Math]::Round(($archiveNeutral / $archiveAttempts) * 100, 2) } else { 0 }

        $exfilOps = @($impactList | Where-Object { $_.Bucket -eq '7.ExfiltrationPrep' })
        $exfilAttempts = $exfilOps.Count
        $exfilBlocked = 0
        foreach ($impact in $exfilOps) {
            $protected = $true
            foreach ($path in $impact.Paths) {
                $relative = Get-RelativePathFromRoot -Root $area.Path -FullPath $path
                if ($null -ne $relative -and $relativeStatus.ContainsKey($relative) -and $relativeStatus[$relative] -ne 'Intact') {
                    $protected = $false
                    break
                }
            }
            if ($protected) { $exfilBlocked++ }
        }
        $exfilRate = if ($exfilAttempts -gt 0) { [Math]::Round(($exfilBlocked / $exfilAttempts) * 100, 2) } else { 0 }

        $totalFiles = $comparison.FileRecords.Count
        $intactCount = ($comparison.FileRecords | Where-Object { $_.Status -eq 'Intact' }).Count
        $changedCount = ($comparison.FileRecords | Where-Object { $_.Status -eq 'Changed' }).Count
        $missingCount = ($comparison.FileRecords | Where-Object { $_.Status -eq 'Missing' }).Count
        $newCount     = ($comparison.FileRecords | Where-Object { $_.Status -eq 'New' }).Count
        $integrityRate = if ($totalFiles -gt 0) { [Math]::Round(($intactCount / $totalFiles) * 100, 2) } else { 0 }

        $summaryEntries.Add([pscustomobject]@{
            Timestamp                 = Get-Date
            AreaName                  = $area.Name
            TotalOperations           = $plan.Count
            SuccessfulOperations      = ($areaEntries | Where-Object { $_.Success }).Count
            FailedOperations          = ($areaEntries | Where-Object { -not $_.Success }).Count
            IntegrityPreservationRate = $integrityRate
            IntactFiles               = $intactCount
            ChangedFiles              = $changedCount
            MissingFiles              = $missingCount
            NewFiles                  = $newCount
            WriteAttemptCount         = $writeAttempts
            WriteBlockRate            = $writeBlockRate
            ArchiveAttemptCount       = $archiveAttempts
            ArchiveNeutralizationRate = $archiveRate
            ExfilAttemptCount         = $exfilAttempts
            ExfilBlockRate            = $exfilRate
        }) | Out-Null
    }

    $operationEntries | Export-Csv -Path $operationCsv -Encoding UTF8 -NoTypeInformation
    $summaryEntries   | Export-Csv -Path $summaryCsv -Encoding UTF8 -NoTypeInformation
    $fileEntries      | Export-Csv -Path $fileCsv -Encoding UTF8 -NoTypeInformation
    $finalStateEntries| Export-Csv -Path $finalCsv -Encoding UTF8 -NoTypeInformation
    "[End] $(Get-Date -Format o) 결과 CSV: $operationCsv" | Out-File -FilePath $logPath -Append -Encoding UTF8
    "[Summary] $summaryCsv" | Out-File -FilePath $logPath -Append -Encoding UTF8
    "[Files] $fileCsv" | Out-File -FilePath $logPath -Append -Encoding UTF8
    "[FinalState] $finalCsv" | Out-File -FilePath $logPath -Append -Encoding UTF8

    return [pscustomobject]@{
        OperationReport = $operationCsv
        SummaryReport   = $summaryCsv
        FileReport      = $fileCsv
        FinalStateReport= $finalCsv
        AtomicsPath     = $atomicsPath
        Entries         = $operationEntries
        Summary         = $summaryEntries
        FileRecords     = $finalStateEntries
    }
}

function Get-AreaSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AreaPath,
        [Parameter(Mandatory)][string]$AreaName
    )

    Write-Verbose "[$AreaName] 파일 무결성 스냅샷을 수집하는 중입니다."
    # Docs, SysCfg 폴더 중심으로 모든 파일을 확인하여 해시(SHA256)와 용량, 수정일을 기록합니다.
    $targets = @()
    $docsPath = Join-Path $AreaPath 'Docs'
    $sysPath  = Join-Path $AreaPath 'SysCfg'
    if (Test-Path -LiteralPath $docsPath) { $targets += $docsPath }
    if (Test-Path -LiteralPath $sysPath) { $targets += $sysPath }
    $files = foreach ($target in $targets) {
        Get-ChildItem -Path $target -File -Recurse -ErrorAction SilentlyContinue
    }
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
    $intact   = @()
    $fileRecords = New-Object System.Collections.Generic.List[object]

    foreach ($key in $Baseline.Keys) {
        if (-not $Current.ContainsKey($key)) {
            $missing += $Baseline[$key]
            $fileRecords.Add([pscustomobject]@{
                RelativePath = $key
                Status       = 'Missing'
                BaselineHash = $Baseline[$key].Hash
                CurrentHash  = $null
                Note         = '기준 대비 파일이 사라졌습니다.'
            }) | Out-Null
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
            $fileRecords.Add([pscustomobject]@{
                RelativePath = $key
                Status       = 'Changed'
                BaselineHash = $baseEntry.Hash
                CurrentHash  = $curEntry.Hash
                Note         = '내용 변경 또는 암호화 가능성'
            }) | Out-Null
        }
        elseif ($baseEntry.Extension -ne $curEntry.Extension) {
            $modified += [pscustomobject]@{
                RelativePath = $key
                PreviousHash = $baseEntry.Hash
                CurrentHash  = $curEntry.Hash
                Comment      = '확장자 변경 탐지'
            }
            $fileRecords.Add([pscustomobject]@{
                RelativePath = $key
                Status       = 'Changed'
                BaselineHash = $baseEntry.Hash
                CurrentHash  = $curEntry.Hash
                Note         = '확장자 변경 탐지'
            }) | Out-Null
        }
        else {
            $intact += $baseEntry
            $fileRecords.Add([pscustomobject]@{
                RelativePath = $key
                Status       = 'Intact'
                BaselineHash = $baseEntry.Hash
                CurrentHash  = $curEntry.Hash
                Note         = '무결성 유지'
            }) | Out-Null
        }
    }

    foreach ($key in $Current.Keys) {
        if (-not $Baseline.ContainsKey($key)) {
            $newFiles += $Current[$key]
            $fileRecords.Add([pscustomobject]@{
                RelativePath = $key
                Status       = 'New'
                BaselineHash = $null
                CurrentHash  = $Current[$key].Hash
                Note         = '기준 스냅샷에 없던 신규 파일'
            }) | Out-Null
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
        IntactCount     = $intact.Count
        ModifiedDetails = $modified
        MissingDetails  = $missing
        NewFileDetails  = $newFiles
        FileRecords     = $fileRecords
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

    Write-Warning 'RanSim이 설치되어 있지 않습니다. 최신 패키지를 자동으로 내려받아 설치합니다.'
    # 최신 RanSim 패키지 다운로드 주소입니다. 필요 시 보안망에서 미리 다운로드해 두세요.
    $downloadUrl = 'https://assets.knowbe4.com/download/ransim/KnowBe4RanSim.zip'
    $localZip    = Join-Path $StagingPath 'KnowBe4RanSim.zip'
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $localZip -UseBasicParsing
        Write-Host "RanSim 설치 패키지를 다운로드했습니다: $localZip"
        Expand-Archive -Path $localZip -DestinationPath $StagingPath -Force
        $installer = Get-ChildItem -Path $StagingPath -Filter 'RanSim*.msi' -Recurse | Select-Object -First 1
        if ($null -ne $installer) {
            $arguments = "/i `"$($installer.FullName)`" /qn /norestart"
            Write-Host 'RanSim 설치 관리자를 무인 설치 모드로 실행합니다.' -ForegroundColor Yellow
            try {
                $proc = Start-Process -FilePath msiexec.exe -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
                Write-Host "RanSim 설치 프로세스가 종료되었습니다 (ExitCode=$($proc.ExitCode))." -ForegroundColor Green
            }
            catch {
                Write-Warning "RanSim 무인 설치 중 오류 발생: $($_.Exception.Message)"
            }
        }
        else {
            Write-Warning 'RanSim 설치 파일을 찾지 못했습니다. 압축 해제된 폴더를 확인하세요.'
        }
    }
    catch {
        Write-Warning "RanSim 다운로드 중 오류 발생: $($_.Exception.Message)"
    }
    $ranSimExe = 'C:\\KB4\\Newsim\\Ranstart.exe'
    if (Test-Path -LiteralPath $ranSimExe) {
        Write-Host 'RanSim 실행 파일을 자동으로 시작합니다.' -ForegroundColor Yellow
        try {
            $ranProc = Start-Process -FilePath $ranSimExe -PassThru -ErrorAction Stop
            try {
                Wait-Process -Id $ranProc.Id -Timeout 900
            }
            catch {
                Write-Warning 'RanSim이 15분 이내에 종료되지 않았습니다. 실행 상태를 직접 확인하세요.'
            }
        }
        catch {
            Write-Warning "RanSim 실행 중 오류 발생: $($_.Exception.Message)"
        }
    }
    return $null
}

function Ensure-AtomicRedTeam {
    [CmdletBinding()]
    param()

    $result = [pscustomobject]@{
        Ready       = $false
        AtomicsPath = $null
        ModuleBase  = $null
    }

    # PowerShell 모듈 Invoke-AtomicRedTeam 설치 여부 확인 후 필요 시 설치합니다.
    $modules = Get-Module -ListAvailable -Name Invoke-AtomicRedTeam
    if (-not $modules) {
        Write-Warning 'Invoke-AtomicRedTeam 모듈이 없습니다. PowerShell 갤러리에서 자동 설치를 시도합니다.'
        try {
            Install-Module -Name Invoke-AtomicRedTeam -Scope AllUsers -Force -ErrorAction Stop
            Write-Host 'Invoke-AtomicRedTeam 모듈 설치가 완료되었습니다.' -ForegroundColor Green
            $modules = Get-Module -ListAvailable -Name Invoke-AtomicRedTeam
        }
        catch {
            Write-Warning "Invoke-AtomicRedTeam 설치 실패: $($_.Exception.Message)"
            return $result
        }
    }

    if (-not $modules) {
        return $result
    }

    $primary = $modules | Select-Object -First 1
    $result.Ready = $true
    if ($primary.ModuleBase) {
        $result.ModuleBase = $primary.ModuleBase
        Write-Host "Invoke-AtomicRedTeam 모듈이 확인되었습니다. (경로: $($primary.ModuleBase))" -ForegroundColor Green
    }
    else {
        Write-Host 'Invoke-AtomicRedTeam 모듈이 확인되었습니다.' -ForegroundColor Green
    }

    $preferred = @()
    if ($primary.ModuleBase) {
        $preferred += (Join-Path $primary.ModuleBase 'atomics')
        $preferred += (Join-Path $primary.ModuleBase 'atomic-red-team-master\\atomics')
    }

    $atomicsPath = Resolve-AtomicsFolder -PreferredPaths $preferred
    if (-not $atomicsPath) {
        # 기본 설치 경로(C:\AtomicRedTeam)에 atomics 폴더가 있는지 다시 확인합니다.
        $defaultRoot = 'C:\\AtomicRedTeam'
        $existing = Resolve-AtomicsFolder -PreferredPaths @(
            (Join-Path $defaultRoot 'atomic-red-team-master\\atomics'),
            (Join-Path $defaultRoot 'atomics')
        )

        if ($existing) {
            $atomicsPath = $existing
        }
    }

    if (-not $atomicsPath) {
        Write-Warning 'Invoke-AtomicRedTeam 모듈은 있으나 atomics 폴더가 보이지 않습니다. GitHub 저장소를 자동으로 내려받습니다.'
        $downloadRoot = 'C:\\AtomicRedTeam'
        $repoUrl = 'https://github.com/redcanaryco/atomic-red-team/archive/refs/heads/master.zip'
        try {
            if (-not (Test-Path -LiteralPath $downloadRoot)) {
                New-Item -ItemType Directory -Path $downloadRoot -Force | Out-Null
            }

            $zipPath = Join-Path $downloadRoot 'atomic-red-team.zip'
            Invoke-WebRequest -Uri $repoUrl -OutFile $zipPath -UseBasicParsing
            Expand-Archive -Path $zipPath -DestinationPath $downloadRoot -Force
            Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue

            $expanded = Join-Path $downloadRoot 'atomic-red-team-master'
            $atomicsPath = Resolve-AtomicsFolder -PreferredPaths @(
                (Join-Path $expanded 'atomics'),
                (Join-Path $downloadRoot 'atomics')
            )

            if ($atomicsPath) {
                Write-Host "Atomic Red Team Atomics 데이터를 다운로드하여 배치했습니다: $atomicsPath" -ForegroundColor Green
            }
        }
        catch {
            Write-Warning "Atomics 패키지 다운로드 실패: $($_.Exception.Message)"
        }
    }

    if ($atomicsPath) {
        $result.AtomicsPath = $atomicsPath
    }
    else {
        Write-Warning 'atomics 폴더 확보에 실패했습니다. 필요 시 https://github.com/redcanaryco/atomic-red-team 저장소를 직접 내려받아 ATOMIC_RED_TEAM_PATH 환경 변수를 설정하세요.'
    }

    return $result
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

    Write-Warning 'Caldera가 설치되어 있지 않습니다. GitHub 릴리스를 자동으로 내려받아 압축을 풉니다.'
    $downloadUrl = 'https://github.com/mitre/caldera/archive/refs/heads/master.zip'
    $localZip    = Join-Path $StagingPath 'caldera-master.zip'
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $localZip -UseBasicParsing
        Write-Host "Caldera 패키지를 다운로드했습니다: $localZip"
        $destination = Join-Path $StagingPath 'caldera-master'
        Expand-Archive -Path $localZip -DestinationPath $destination -Force
        Write-Host 'Caldera 압축을 해제했습니다. 가상 환경 및 서버 기동은 README 절차에 따라 진행하세요.' -ForegroundColor Yellow
        return $destination
    }
    catch {
        Write-Warning "Caldera 다운로드 실패: $($_.Exception.Message)"
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

        Write-Host (
            "    - 변경 파일: {0}, 신규 파일: {1}, 누락 파일: {2}" -f `
            $result.ModifiedCount, $result.NewFileCount, $result.MissingCount
        ) -ForegroundColor DarkCyan
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

$documentPlan = New-DocumentSelectionPlan
$planCsv = Export-DocumentSelectionPlan -Plan $documentPlan -ReportPath $reportPath
Write-Host "문서 샘플 구성 계획을 CSV로 저장했습니다 (Seed: $($documentPlan.Seed)): $planCsv" -ForegroundColor Green

foreach ($area in $areas) {
    $context = Initialize-AreaData -AreaName $area.Name -TargetPath $area.Path -DocumentPlan $documentPlan
    $area | Add-Member -NotePropertyName Context -NotePropertyValue $context -Force
    Write-Host "[$($area.Name)] Docs: $($context.DocsPath) / SysCfg: $($context.SysCfgPath)" -ForegroundColor Green
}

# 3단계: 생성된 데이터를 바탕으로 데이터 보호 성능을 평가합니다.
Measure-DataProtectionBaseline -Areas $areas -ReportPath $reportPath | Out-Null

# 4단계: 랜섬웨어/악성코드 비교 전에 현재 상태를 기준선으로 저장합니다.
$baselines = @{}
foreach ($area in $areas) {
    $baselines[$area.Name] = Get-AreaSnapshot -AreaPath $area.Path -AreaName $area.Name
}

# 5단계: Atomic Red Team 모듈을 점검하고 악성코드 성능 검증을 수행합니다.
$atomicInfo = Ensure-AtomicRedTeam
$malwareResults = Invoke-MalwareAssessment -AtomicContext $atomicInfo -Areas $areas -ReportPath $reportPath -Baselines $baselines
if ($malwareResults) {
    Write-Host "악성코드 성능 평가 보고서를 생성했습니다: $($malwareResults.SummaryReport)" -ForegroundColor Green
    Write-Host "파일 단위 악성코드 검증 결과: $($malwareResults.FileReport)" -ForegroundColor Green
    if ($malwareResults.PSObject.Properties.Name -contains 'FinalStateReport') {
        Write-Host "악성코드 실행 후 최종 파일 상태 요약: $($malwareResults.FinalStateReport)" -ForegroundColor Green
    }
}

Write-Host '기본 무결성 스냅샷을 완료했습니다. 시뮬레이터 준비 상태를 확인합니다.' -ForegroundColor Cyan
$staging = Join-Path $reportPath "SimulatorPackages_$(Get-Date -Format yyyyMMddHHmmss)"
New-Item -ItemType Directory -Path $staging -Force | Out-Null

# 6단계: RanSim, Caldera가 설치되어 있는지 확인하고 필요 시 설치 안내를 제공합니다.
$ransomExe = Ensure-RanSim -StagingPath $staging
$calderaPath = Ensure-Caldera -StagingPath $staging

if (-not $atomicInfo.Ready) {
    Write-Host 'Atomic Red Team 모듈이 준비되지 않아 내부 시뮬레이션만 실행됩니다.' -ForegroundColor Yellow
}
elseif ($atomicInfo.AtomicsPath) {
    Write-Host "Atomic Red Team atomics 폴더: $($atomicInfo.AtomicsPath)" -ForegroundColor DarkGreen
}

# 7단계: 시뮬레이터 실행 이후 변경된 내용을 분석하여 결과를 정리합니다.
$evaluation = Evaluate-Areas -Areas $areas -Baselines $baselines

$csvPath = Join-Path $reportPath ("Ransomware_Evaluation_{0}.csv" -f (Get-Date -Format yyyyMMdd_HHmmss))
$flatReport = foreach ($item in $evaluation) {
    [pscustomobject]@{
        Timestamp       = (Get-Date)
        AreaName        = $item.AreaName
        IntactFiles     = $item.IntactCount
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

$fileStatusCsv = Join-Path $reportPath ("Ransomware_FileStatus_{0}.csv" -f (Get-Date -Format yyyyMMdd_HHmmss))
$fileStatus = foreach ($item in $evaluation) {
    foreach ($record in $item.FileRecords) {
        [pscustomobject]@{
            Timestamp     = (Get-Date)
            AreaName      = $item.AreaName
            RelativePath  = $record.RelativePath
            Status        = $record.Status
            BaselineHash  = $record.BaselineHash
            CurrentHash   = $record.CurrentHash
            Note          = $record.Note
        }
    }
}
$fileStatus | Export-Csv -Path $fileStatusCsv -Encoding UTF8 -NoTypeInformation
Write-Host "파일 단위 결과 CSV 파일을 생성했습니다: $fileStatusCsv" -ForegroundColor Green

Write-Host '=== 검증이 완료되었습니다. 결과 파일을 확인하세요. ===' -ForegroundColor Cyan
