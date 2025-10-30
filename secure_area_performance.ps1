#requires -Version 5.1
<#!
    보안 영역 저장 장치 성능 평가 자동화 스크립트
    ------------------------------------------------------------
    본 스크립트는 보안 영역(대상 폴더)을 초기화하고, 표준 샘플 데이터를 생성하여
    쓰기/읽기/무결성 검증을 수행한 뒤 CSV, XLSX, DOCX 결과를 자동으로 생성합니다.

    사용 순서
    1. 저장장치 종류, 보안영역 경로, 샘플데이터 보관 경로, 결과 저장 경로를 입력합니다.
    2. 샘플데이터 폴더가 없으면 새로 생성하고 문서·시스템 샘플을 채웁니다.
    3. 보안영역 폴더의 기존 내용을 정리하고 샘플을 복사합니다.
    4. 각 파일의 쓰기/읽기/해시를 검증하여 세부/요약 결과를 산출합니다.
    5. 결과 CSV와 XLSX, DOCX 분석 보고서를 생성합니다.

    관리자 권한 PowerShell에서 실행하는 것을 권장합니다.
!#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.IO.Compression.FileSystem

#region 공통 입출력 유틸리티
function Read-RequiredValue {
    param(
        [Parameter(Mandatory)] [string] $PromptText
    )
    while ($true) {
        $value = Read-Host -Prompt $PromptText
        if ([string]::IsNullOrWhiteSpace($value)) {
            Write-Host '값을 입력해야 합니다. 다시 시도해 주세요.' -ForegroundColor Yellow
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

#region 장치 정보 도우미
function Normalize-DeviceType {
    param([string] $Input)
    if ([string]::IsNullOrWhiteSpace($Input)) { return 'Unknown' }
    $value = $Input.Trim()
    $upper = $value.ToUpper()
    switch -Regex ($upper) {
        '^(1|HDD)' { return 'HDD' }
        '^(2|SSD|NVME|M\.2|PCIE|SATA|SAS)' { return 'SSD/NVMe' }
        '^(3|USB)' { return 'USB' }
        '^(4|ETC|기타|OTHER)' { return 'ETC' }
        default { return $value }
    }
}

function Get-DeviceAttributesFromPath {
    param([string] $Path)
    try {
        if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
        $root = [System.IO.Path]::GetPathRoot($Path)
        if ([string]::IsNullOrWhiteSpace($root)) { return $null }
        $drive = $root.TrimEnd('\')
        $ld = Get-WmiObject -Class Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $drive) -ErrorAction Stop
        if (-not $ld) { return $null }
        $partitions = Get-WmiObject -Query ("ASSOCIATORS OF {{Win32_LogicalDisk.DeviceID='{0}'}} WHERE ResultClass=Win32_DiskPartition" -f $drive) -ErrorAction Stop
        foreach ($part in $partitions) {
            $drives = Get-WmiObject -Query ("ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{0}'}} WHERE ResultClass=Win32_DiskDrive" -f $part.DeviceID.Replace('\\','\\\\')) -ErrorAction SilentlyContinue
            foreach ($d in $drives) {
                $parts = @()
                if ($d.Model) { $parts += $d.Model }
                if ($d.InterfaceType) { $parts += $d.InterfaceType }
                if ($d.MediaType) { $parts += $d.MediaType }
                if ($d.SerialNumber) { $parts += ("SN:" + $d.SerialNumber) }
                if ($parts.Count -gt 0) { return ($parts -join ' / ') }
            }
        }
        return $null
    }
    catch { return $null }
}
#endregion

#region XLSX / DOCX 생성 유틸리티
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
    if ($rowsList.Count -eq 0) {
        return "<worksheet xmlns='http://schemas.openxmlformats.org/spreadsheetml/2006/main'><sheetData/></worksheet>"
    }
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

        $coreXml = "<?xml version='1.0' encoding='UTF-8'?><cp:coreProperties xmlns:cp='http://schemas.openxmlformats.org/package/2006/metadata/core-properties' xmlns:dc='http://purl.org/dc/elements/1.1/' xmlns:dcterms='http://purl.org/dc/terms/'><dc:title>보안 영역 성능 평가 보고서</dc:title><dc:creator>Security Automation</dc:creator><cp:lastModifiedBy>Security Automation</cp:lastModifiedBy><dcterms:created xsi:type='dcterms:W3CDTF' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'>$(Get-Date -Format s)Z</dcterms:created></cp:coreProperties>"
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

        $builder = New-Object System.Text.StringBuilder
        foreach ($paragraph in $Paragraphs) {
            $escaped = [System.Security.SecurityElement]::Escape($paragraph)
            $builder.Append("<w:p><w:r><w:t xml:space='preserve'>$escaped</w:t></w:r></w:p>") | Out-Null
        }
        $documentXml = "<?xml version='1.0' encoding='UTF-8'?><w:document xmlns:w='http://schemas.openxmlformats.org/wordprocessingml/2006/main'>$builder</w:document>"
        $entry = $zip.CreateEntry('word/document.xml')
        $writer = New-Object System.IO.StreamWriter($entry.Open())
        $writer.Write($documentXml)
        $writer.Dispose()

        $coreXml = "<?xml version='1.0' encoding='UTF-8'?><cp:coreProperties xmlns:cp='http://schemas.openxmlformats.org/package/2006/metadata/core-properties' xmlns:dc='http://purl.org/dc/elements/1.1/' xmlns:dcterms='http://purl.org/dc/terms/'><dc:title>보안 영역 성능 평가 보고서</dc:title><dc:creator>Security Automation</dc:creator><cp:lastModifiedBy>Security Automation</cp:lastModifiedBy><dcterms:created xsi:type='dcterms:W3CDTF' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'>$(Get-Date -Format s)Z</dcterms:created></cp:coreProperties>"
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

#region 샘플 데이터 생성
function New-DocumentPlan {
    param([int] $Seed)
    $rand = [System.Random]::new($Seed)
    $sizeOptions = @(65536, 262144, 1048576)
    $extensions = @('doc','docx','ppt','pptx','xls','xlsx','hwp','hwpx','txt')
    $plan = New-Object System.Collections.ArrayList
    foreach ($ext in $extensions) {
        $size = $sizeOptions[$rand.Next(0, $sizeOptions.Count)]
        $fileName = "sample_{0}_{1}.{0}" -f $ext, $size
        $bytes = New-Object byte[] $size
        $rand.NextBytes($bytes)
        [void]$plan.Add([PSCustomObject]@{ FileName = $fileName; Bytes = $bytes; Category = 'Docs' })
    }
    return $plan
}

function Initialize-SampleDataset {
    param(
        [string] $DatasetRoot,
        [System.Collections.IEnumerable] $DocumentPlan,
        [byte[]] $UsrClassBytes,
        [byte[]] $DllBytes
    )
    Write-Host "[Dataset] 샘플 데이터를 준비합니다: $DatasetRoot"
    Ensure-Directory -Path $DatasetRoot
    Clear-Directory -Path $DatasetRoot

    $docsPath = Join-Path $DatasetRoot 'Docs'
    $sysPath = Join-Path $DatasetRoot 'SysCfg'
    Ensure-Directory -Path $docsPath
    Ensure-Directory -Path $sysPath

    foreach ($item in $DocumentPlan) {
        $target = Join-Path $docsPath $item.FileName
        Write-BytesFile -Path $target -Bytes ([byte[]]$item.Bytes.Clone())
    }

    Write-TextFile -Path (Join-Path $sysPath 'hosts_sample.txt') -Content "127.0.0.1 localhost`n# 테스트용 hosts"
    Write-TextFile -Path (Join-Path $sysPath 'system.env') -Content "APP_ENV=SecureAreaTest`nTRACE=true"
    Write-TextFile -Path (Join-Path $sysPath 'appsettings.json') -Content '{"Logging":{"Level":"Information"},"ConnectionStrings":{"Primary":"Server=127.0.0.1;Database=Test"}}'
    Write-TextFile -Path (Join-Path $sysPath 'config.ini') -Content "[General]`nName=SecureArea`nMode=PerformanceTest"
    Write-TextFile -Path (Join-Path $sysPath 'registry_backup.reg') -Content "Windows Registry Editor Version 5.00`n[HKEY_LOCAL_MACHINE\\SOFTWARE\\SampleCompany]`n\"AreaName\"=\"SecureArea\""
    Write-TextFile -Path (Join-Path $sysPath 'sample.csv') -Content "Name,Value`nSample,123"
    Write-TextFile -Path (Join-Path $sysPath 'settings.config') -Content "<?xml version='1.0' encoding='utf-8'?><configuration><appSettings><add key='Mode' value='SecureArea'/></appSettings></configuration>"
    Write-BytesFile -Path (Join-Path $sysPath 'system_like_UsrClass.dat') -Bytes ([byte[]]$UsrClassBytes.Clone())
    Write-BytesFile -Path (Join-Path $sysPath 'sample.dll') -Bytes ([byte[]]$DllBytes.Clone())

    $pngBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/wwAAgMBAJcC/wAAAABJRU5ErkJggg=='
    Write-Base64File -Path (Join-Path $sysPath 'image_1x1.png') -Base64 $pngBase64
    $jpgBase64 = '/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAAkGBxISEhAQEBAQEA8QDxAQEA8PDxAPDxAQFREWFhURFRUYHSggGBolGxUVITEhJSkrLi4uFx8zODMsNygtLisBCgoKDQ0NDg0NDisZFRkrKysrKysrKysrKystKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrK//AABEIAJwBPgMBIgACEQEDEQH/xAAXAAADAQAAAAAAAAAAAAAAAAADBAUG/8QAHBAAAQQDAQAAAAAAAAAAAAAAAQACAxEEEiEx/8QAFwEAAwEAAAAAAAAAAAAAAAAAAQIDBf/EAB4RAAICAQUAAAAAAAAAAAAAAAABAgMEERITIUFR/9oADAMBAAIRAxEAPwDtVLwlh8zvP4STcQduPqbXaW3n1JcTzH//2Q=='
    Write-Base64File -Path (Join-Path $sysPath 'image_1x1.jpg') -Base64 $jpgBase64

    $zipPath = Join-Path $sysPath 'sample.zip'
    New-ZipSample -DestinationPath $zipPath -SourceContent @{ 'readme.txt' = "보안 영역 테스트용 ZIP 입니다." }
}
#endregion

#region 테스트 수행
function Get-RelativePath {
    param([string] $BasePath, [string] $FullPath)
    $base = [System.IO.Path]::GetFullPath((Join-Path $BasePath '.'))
    $full = [System.IO.Path]::GetFullPath($FullPath)
    if ($full.StartsWith($base, [System.StringComparison]::OrdinalIgnoreCase)) {
        $relative = $full.Substring($base.Length)
        return $relative.TrimStart('\')
    }
    return [System.IO.Path]::GetFileName($FullPath)
}

function Copy-And-VerifyFile {
    param(
        [string] $SourcePath,
        [string] $TargetRoot,
        [string] $DatasetRoot,
        [string] $RunId,
        [datetime] $RunStartTime,
        [string] $DeviceType,
        [string] $DeviceAttrs
    )
    $relative = Get-RelativePath -BasePath $DatasetRoot -FullPath $SourcePath
    if (-not $relative) { $relative = [System.IO.Path]::GetFileName($SourcePath) }
    $targetPath = Join-Path $TargetRoot $relative
    Ensure-Directory -Path (Split-Path -Path $targetPath -Parent)

    $fileLength = (Get-Item -LiteralPath $SourcePath).Length

    $result = [PSCustomObject]@{
        RunId        = $RunId
        DeviceType   = $DeviceType
        DeviceAttrs  = if ($DeviceAttrs) { $DeviceAttrs } else { '' }
        TargetFolder = $TargetRoot
        StartTime    = $RunStartTime
        EndTime      = $null
        DurationSec  = 0
        FileName     = [System.IO.Path]::GetFileName($relative)
        RelativePath = $relative
        TargetPath   = $targetPath
        SourcePath   = $SourcePath
        SizeBytes    = $fileLength
        WriteOK      = $false
        ReadOK       = $false
        HashOK       = $false
        DeleteOK     = $false
        Status       = 'FAIL'
        Error        = ''
        Category     = if ($relative -like 'Docs*') { 'Docs' } elseif ($relative -like 'SysCfg*') { 'SysCfg' } else { 'Other' }
    }

    try {
        Copy-Item -LiteralPath $SourcePath -Destination $targetPath -Force
        $result.WriteOK = Test-Path -LiteralPath $targetPath
    }
    catch {
        $result.Error = "COPY_FAIL: $($_.Exception.Message)"
        return $result
    }

    try {
        $sourceHash = (Get-FileHash -LiteralPath $SourcePath -Algorithm SHA256).Hash
        $targetHash = (Get-FileHash -LiteralPath $targetPath -Algorithm SHA256).Hash
        $result.ReadOK = $true
        $result.HashOK = ($sourceHash -eq $targetHash)
        if (-not $result.HashOK) {
            if ($result.Error) { $result.Error += '; ' }
            $result.Error += 'HASH_MISMATCH'
        }
    }
    catch {
        if ($result.Error) { $result.Error += '; ' }
        $result.Error += "HASH_FAIL: $($_.Exception.Message)"
    }

    try {
        if (Test-Path -LiteralPath $targetPath) {
            Remove-Item -LiteralPath $targetPath -Force
        }
        $result.DeleteOK = $true
    }
    catch {
        if ($result.Error) { $result.Error += '; ' }
        $result.Error += "DELETE_FAIL: $($_.Exception.Message)"
    }

    $result.EndTime = Get-Date
    $result.DurationSec = [int]((New-TimeSpan -Start $RunStartTime -End $result.EndTime).TotalSeconds)

    if ($result.WriteOK -and $result.ReadOK -and $result.HashOK -and $result.DeleteOK -and -not $result.Error) {
        $result.Status = 'PASS'
    }
    else {
        $result.Status = 'FAIL'
        if (-not $result.Error) { $result.Error = '검증 실패' }
    }

    return $result
}

function Test-SecureArea {
    param(
        [string] $DatasetRoot,
        [string] $SecureRoot,
        [string] $RunId,
        [datetime] $RunStartTime,
        [string] $DeviceType,
        [string] $DeviceAttrs
    )
    Write-Host "[SecureArea] 샘플 데이터를 복사하고 검증합니다."
    Ensure-Directory -Path $SecureRoot
    Clear-Directory -Path $SecureRoot

    $files = Get-ChildItem -LiteralPath $DatasetRoot -File -Recurse
    $records = New-Object System.Collections.Generic.List[object]
    foreach ($file in $files) {
        $record = Copy-And-VerifyFile -SourcePath $file.FullName -TargetRoot $SecureRoot -DatasetRoot $DatasetRoot -RunId $RunId -RunStartTime $RunStartTime -DeviceType $DeviceType -DeviceAttrs $DeviceAttrs
        $records.Add($record) | Out-Null
        $color = if ($record.Status -eq 'PASS') { 'Green' } else { 'Red' }
        Write-Host " - $($record.RelativePath) : $($record.Status)" -ForegroundColor $color
        if ($record.Error) {
            Write-Host "   > $($record.Error)" -ForegroundColor Yellow
        }
    }
    return $records.ToArray()
}
#endregion

#region 요약 계산
function Get-SummaryRows {
    param([System.Collections.IEnumerable] $Records)
    $list = @($Records)
    $groups = $list | Group-Object -Property Category
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($group in $groups) {
        $total = $group.Count
        $pass = ($group.Group | Where-Object { $_.Status -eq 'PASS' }).Count
        $fail = $total - $pass
        $rows.Add([PSCustomObject]@{
            Stage      = 'SecureArea'
            Category   = $group.Name
            Total      = $total
            Pass       = $pass
            Fail       = $fail
            PassRate   = if ($total -eq 0) { 0 } else { [math]::Round(($pass / $total) * 100, 2) }
        }) | Out-Null
    }
    $overallTotal = $list.Count
    $overallPass = ($list | Where-Object { $_.Status -eq 'PASS' }).Count
    $rows.Add([PSCustomObject]@{
        Stage      = 'SecureArea'
        Category   = '전체'
        Total      = $overallTotal
        Pass       = $overallPass
        Fail       = $overallTotal - $overallPass
        PassRate   = if ($overallTotal -eq 0) { 0 } else { [math]::Round(($overallPass / $overallTotal) * 100, 2) }
    }) | Out-Null
    return $rows.ToArray()
}
#endregion

#region 분석 리포트 문단 생성
function Build-AnalysisParagraphs {
    param(
        [PSCustomObject[]] $SummaryRows,
        [string] $SecurePath,
        [string] $DeviceType,
        [string] $DeviceAttrs,
        [int] $Seed
    )
    $docsRow = $SummaryRows | Where-Object { $_.Category -eq 'Docs' } | Select-Object -First 1
    $sysRow  = $SummaryRows | Where-Object { $_.Category -eq 'SysCfg' } | Select-Object -First 1
    $overall = $SummaryRows | Where-Object { $_.Category -eq '전체' } | Select-Object -First 1

    $docsLine = if ($docsRow) {
        "문서 데이터(Intact $($docsRow.Pass), Fail $($docsRow.Fail), PassRate $($docsRow.PassRate)%): 모든 문서 파일에 대해 쓰기·읽기·해시 검증을 수행했습니다."
    } else {
        '문서 데이터 결과를 찾을 수 없습니다.'
    }
    $sysLine = if ($sysRow) {
        "시스템/환경 데이터(Intact $($sysRow.Pass), Fail $($sysRow.Fail), PassRate $($sysRow.PassRate)%): 환경 설정, DLL, 레지스트리 백업 등 시스템성 파일을 동일하게 검증했습니다."
    } else {
        '시스템/환경 데이터 결과를 찾을 수 없습니다.'
    }
    $overallLine = if ($overall) {
        "전체 결과: 총 $($overall.Total)건 중 $($overall.Pass)건 PASS, $($overall.Fail)건 FAIL (성공률 $($overall.PassRate)% )."
    } else {
        '전체 합계 정보를 찾을 수 없습니다.'
    }

    $deviceInfo = if ($DeviceAttrs) {
        "장치 속성: $DeviceAttrs"
    } else {
        '장치 속성: 자동 수집 실패'
    }

    return @(
        '평가 결과 요약',
        '보고서는 보안 영역에 표준 문서·시스템 데이터를 배포한 뒤 쓰기/읽기/무결성(Hash) 검증을 수행한 결과를 정리한 것입니다.',
        "보안영역 경로: $SecurePath",
        "저장장치 유형: $DeviceType",
        $deviceInfo,
        $overallLine,
        '',
        '문서 데이터 쓰기/읽기 검증',
        $docsLine,
        '• 문서 확장자 9종(doc, docx, ppt, pptx, xls, xlsx, hwp, hwpx, txt)을 대상으로 무작위 크기(64KB, 256KB, 1MB)를 선정했습니다.',
        '',
        '시스템 및 환경 데이터 검증',
        $sysLine,
        '• hosts, system.env, appsettings.json, config.ini, registry_backup.reg, sample.csv 등 5종 이상의 환경 파일과 DLL, DAT, 이미지, ZIP 등을 포함합니다.',
        '',
        '시사점',
        '• PASS 건수가 100%가 아닐 경우, 실패한 항목의 오류 메시지를 참고하여 접근 권한, 잠금 프로세스, 실시간 보안 정책을 점검하세요.',
        '• 모든 항목이 PASS라면 보안 영역이 테스트 데이터에 대해 정상적으로 쓰기/읽기/무결성 보장을 수행한 것입니다.',
        '',
        '권장 후속 조치',
        '• 정기적으로 동일한 시나리오를 반복하여 저장장치 상태 변화 여부를 확인하세요.',
        '• 테스트 후 불필요한 임시 파일이나 로그를 정리하고, 필요 시 결과 CSV/XLSX를 장기 보관하세요.',
        '• 보안 영역에 대한 백업 정책이 있다면 이번 평가 결과를 증적 자료로 연계해 두는 것이 좋습니다.',
        '',
        "추가 정보: 난수 시드 $Seed"
    )
}
#endregion

#region 메인 실행
Write-Host '=== 보안 영역 성능 평가 자동화 시작 ==='
$deviceTypeInput = Read-RequiredValue -PromptText '저장장치 종류(가장 먼저 입력). 예: 1, 2, 3, 4 또는 HDD/SSD/USB/ETC, NVMe 등'
$secureRoot = Read-RequiredValue -PromptText '대상 보안영역 위치 (예: E:\\SecureArea)'
$datasetRoot = Read-RequiredValue -PromptText '샘플 데이터 위치 (예: D:\\dataset) - 없으면 자동 생성 후 1MB/64MB/256MB 파일을 만듭니다.'
$resultInput = Read-RequiredValue -PromptText '결과 데이터 저장 위치 (폴더 또는 .csv 파일 경로, 예: E:\\logs 또는 E:\\logs\\SecureArea_test_results.csv)'

$deviceType = Normalize-DeviceType -Input $deviceTypeInput
$deviceAttrs = Get-DeviceAttributesFromPath -Path $secureRoot

$runStartTime = Get-Date
$runId = $runStartTime.ToString('yyyyMMdd_HHmmss')
$seed = Get-Random -Maximum 1000000
$docPlan = New-DocumentPlan -Seed $seed
$usrClassBytes = New-Object byte[] 4096
$dllBytes = New-Object byte[] 32768
$rand = [System.Random]::new($seed)
$rand.NextBytes($usrClassBytes)
$rand.NextBytes($dllBytes)

Initialize-SampleDataset -DatasetRoot $datasetRoot -DocumentPlan $docPlan -UsrClassBytes $usrClassBytes -DllBytes $dllBytes
Write-Host "샘플 데이터 생성 완료 (Seed: $seed)" -ForegroundColor Cyan

$records = Test-SecureArea -DatasetRoot $datasetRoot -SecureRoot $secureRoot -RunId $runId -RunStartTime $runStartTime -DeviceType $deviceType -DeviceAttrs $deviceAttrs
$summaryRows = Get-SummaryRows -Records $records

$useFileTarget = $resultInput -match '\\.xlsx$'
if ($useFileTarget) {
    $reportDirectory = Split-Path -Path $resultInput -Parent
    if ([string]::IsNullOrWhiteSpace($reportDirectory)) { $reportDirectory = (Get-Location).Path }
} else {
    $reportDirectory = $resultInput
}
Ensure-Directory -Path $reportDirectory
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

$csvFolder = Join-Path $reportDirectory 'csv'
Ensure-Directory -Path $csvFolder
$jsonFolder = Join-Path $reportDirectory 'json'
Ensure-Directory -Path $jsonFolder

$detailCsv = Join-Path $csvFolder "SecureArea_TestDetails_${timestamp}.csv"
$summaryCsv = Join-Path $csvFolder "SecureArea_TestSummary_${timestamp}.csv"
$detailJson = Join-Path $jsonFolder "SecureArea_TestDetails_${timestamp}.json"

$detailRows = $records | ForEach-Object {
    $errorText = if ([string]::IsNullOrWhiteSpace($_.Error)) { 'X' } else { $_.Error }
    [PSCustomObject]@{
        RunId        = $_.RunId
        DeviceType   = $_.DeviceType
        DeviceAttrs  = $_.DeviceAttrs
        TargetFolder = $_.TargetFolder
        Start        = $_.StartTime.ToString('s')
        End          = $_.EndTime.ToString('s')
        DurationSec  = $_.DurationSec
        FileName     = $_.FileName
        SizeBytes    = $_.SizeBytes
        WriteOK      = $_.WriteOK
        ReadOK       = $_.ReadOK
        HashOK       = $_.HashOK
        DeleteOK     = $_.DeleteOK
        Error        = $errorText
    }
}

$detailRows | Export-Csv -Path $detailCsv -NoTypeInformation -Encoding UTF8
$summaryRows | Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding UTF8
$records | ConvertTo-Json -Depth 5 | Out-File -FilePath $detailJson -Encoding UTF8

$excelPath = if ($useFileTarget) { $resultInput } else { Join-Path $reportDirectory "SecureArea_TestReport_${timestamp}.xlsx" }
$sheetData = @(
    @{ Name = 'Summary'; Rows = $summaryRows },
    @{ Name = 'Details'; Rows = $records }
)
New-SimpleWorkbook -Path $excelPath -Sheets $sheetData

$docxPath = Join-Path $reportDirectory "Analysis_Report_${timestamp}.docx"
$analysisParagraphs = @(
    '보안 영역 저장 장치 성능 평가 보고서',
    "생성 일시: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
    "보안영역 경로: $secureRoot",
    "저장장치 유형: $deviceType",
    $(if ($deviceAttrs) { "장치 속성: $deviceAttrs" } else { '장치 속성: 자동 수집 실패' }),
    "총 파일 수: $($records.Count)",
    ''
) + (Build-AnalysisParagraphs -SummaryRows $summaryRows -SecurePath $secureRoot -DeviceType $deviceType -DeviceAttrs $deviceAttrs -Seed $seed)
New-SimpleDocx -Path $docxPath -Paragraphs $analysisParagraphs

Write-Host '--- 생성된 결과 ---'
Write-Host "세부 CSV : $detailCsv"
Write-Host "요약 CSV : $summaryCsv"
Write-Host "세부 JSON : $detailJson"
Write-Host "엑셀 보고서 : $excelPath"
Write-Host "워드 보고서 : $docxPath"
Write-Host '=== 보안 영역 성능 평가가 완료되었습니다. ==='
#endregion
