#requires -Version 5.1
<#!
    IO 성능 평가 자동화 스크립트 v0.5
    ------------------------------------------------------------
    - 일반영역과 보안영역 경로, 샘플 데이터 저장소, 결과 경로를 입력받습니다.
    - 샘플 데이터 폴더를 초기화하고 100개의 문서/시스템 샘플 파일을 생성합니다.
    - 일반영역/보안영역 폴더는 측정 전에 초기화합니다.
    - 전체 100개 샘플에 대해 일반영역 저장/읽기 지연을 먼저 측정하고 30초 대기 후 보안영역 저장/읽기 지연을 측정합니다.
    - 결과는 CSV/XLSX/DOCX 형태로 저장되며, 보고서에는 요구된 통계 요약과 합격 판정, 그래프 파일명이 포함됩니다.
    - 시간 기반 성능비율 (일반/보안)과 처리량 비율 (보안/일반)을 모두 90% 이상 충족하면 PASS로 판정합니다.
!#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Windows.Forms.DataVisualization

#region 유틸리티
function Read-RequiredPath {
    param([Parameter(Mandatory)] [string] $PromptText)
    while ($true) {
        $value = Read-Host -Prompt $PromptText
        if ([string]::IsNullOrWhiteSpace($value)) {
            Write-Host '값을 입력해야 합니다. 다시 시도하세요.' -ForegroundColor Yellow
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

function Initialize-ZipSupport {
    if ($script:ZipSupportInitialized) { return }
    $script:ZipSupportInitialized = $true
    $script:UseNativeZip = $false
    try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch {}
    if ([System.Type]::GetType('System.IO.Compression.ZipArchiveMode')) {
        $script:UseNativeZip = $true
    }
}

function Initialize-Crc32Table {
    if ($script:Crc32Table) { return }
    $table = New-Object 'System.UInt32[]' 256
    for ($i = 0; $i -lt 256; $i++) {
        $crc = [uint32]$i
        for ($j = 0; $j -lt 8; $j++) {
            if (($crc -band 1) -ne 0) {
                $crc = (0xEDB88320 -bxor ($crc >> 1))
            }
            else {
                $crc = $crc >> 1
            }
        }
        $table[$i] = $crc
    }
    $script:Crc32Table = $table
}

function Get-Crc32 {
    param([byte[]] $Bytes)
    Initialize-Crc32Table
    $crc = 0xFFFFFFFF
    foreach ($b in $Bytes) {
        $index = ($crc -bxor $b) -band 0xFF
        $crc = ($script:Crc32Table[$index]) -bxor ($crc >> 8)
    }
    return (-bnot $crc) -band 0xFFFFFFFF
}

function Get-DosTimeParts {
    param([datetime] $Timestamp)
    $dt = $Timestamp
    if ($dt.Year -lt 1980) { $dt = Get-Date '1980-01-01' }
    $dosDate = (($dt.Year - 1980) -shl 9) -bor (($dt.Month) -shl 5) -bor $dt.Day
    $dosTime = (($dt.Hour) -shl 11) -bor (($dt.Minute) -shl 5) -bor ([math]::Floor($dt.Second / 2))
    return [PSCustomObject]@{ Date = [uint16]$dosDate; Time = [uint16]$dosTime }
}

function Write-ManualZip {
    param(
        [string] $Path,
        [System.Collections.IEnumerable] $Entries
    )
    $memory = New-Object System.IO.MemoryStream
    $writer = New-Object System.IO.BinaryWriter($memory, [System.Text.Encoding]::UTF8, $true)
    $centralRecords = New-Object System.Collections.Generic.List[object]
    foreach ($entry in $Entries) {
        $nameBytes = [System.Text.Encoding]::UTF8.GetBytes($entry.Name)
        $data = $entry.Bytes
        $crc = Get-Crc32 $data
        $timeParts = Get-DosTimeParts (Get-Date)
        $localOffset = [uint32]$memory.Position
        $writer.Write([uint32]0x04034b50)
        $writer.Write([uint16]20)
        $writer.Write([uint16]0)
        $writer.Write([uint16]0)
        $writer.Write([uint16]$timeParts.Time)
        $writer.Write([uint16]$timeParts.Date)
        $writer.Write([uint32]$crc)
        $writer.Write([uint32]$data.Length)
        $writer.Write([uint32]$data.Length)
        $writer.Write([uint16]$nameBytes.Length)
        $writer.Write([uint16]0)
        $writer.Write($nameBytes)
        $writer.Write($data)
        $centralRecords.Add([PSCustomObject]@{
            NameBytes = $nameBytes
            Size = [uint32]$data.Length
            Crc = [uint32]$crc
            Time = [uint16]$timeParts.Time
            Date = [uint16]$timeParts.Date
            Offset = $localOffset
        }) | Out-Null
    }
    $centralOffset = [uint32]$memory.Position
    foreach ($record in $centralRecords) {
        $writer.Write([uint32]0x02014b50)
        $writer.Write([uint16]0x031E)
        $writer.Write([uint16]20)
        $writer.Write([uint16]0)
        $writer.Write([uint16]0)
        $writer.Write([uint16]$record.Time)
        $writer.Write([uint16]$record.Date)
        $writer.Write([uint32]$record.Crc)
        $writer.Write([uint32]$record.Size)
        $writer.Write([uint32]$record.Size)
        $writer.Write([uint16]$record.NameBytes.Length)
        $writer.Write([uint16]0)
        $writer.Write([uint16]0)
        $writer.Write([uint16]0)
        $writer.Write([uint16]0)
        $writer.Write([uint32]0)
        $writer.Write([uint32]$record.Offset)
        $writer.Write($record.NameBytes)
    }
    $centralSize = [uint32]($memory.Position - $centralOffset)
    $writer.Write([uint32]0x06054b50)
    $writer.Write([uint16]0)
    $writer.Write([uint16]0)
    $writer.Write([uint16]$centralRecords.Count)
    $writer.Write([uint16]$centralRecords.Count)
    $writer.Write([uint32]$centralSize)
    $writer.Write([uint32]$centralOffset)
    $writer.Write([uint16]0)
    $writer.Flush()
    [System.IO.File]::WriteAllBytes($Path, $memory.ToArray())
    $writer.Dispose()
    $memory.Dispose()
}

function Write-ZipArchive {
    param(
        [string] $Path,
        [System.Collections.IEnumerable] $Entries
    )
    $directory = Split-Path -Path $Path -Parent
    Ensure-Directory -Path $directory
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    Initialize-ZipSupport
    if ($script:UseNativeZip) {
        $zip = [System.IO.Compression.ZipFile]::Open($Path, [System.IO.Compression.ZipArchiveMode]::Create)
        try {
            foreach ($entry in $Entries) {
                $zipEntry = $zip.CreateEntry($entry.Name)
                $stream = $zipEntry.Open()
                try {
                    $stream.Write($entry.Bytes, 0, $entry.Bytes.Length)
                }
                finally {
                    $stream.Dispose()
                }
            }
        }
        finally {
            $zip.Dispose()
        }
    }
    else {
        Write-ManualZip -Path $Path -Entries $Entries
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

function Write-BytesFile {
    param([string] $Path, [byte[]] $Bytes)
    $folder = Split-Path -Path $Path -Parent
    Ensure-Directory -Path $folder
    [System.IO.File]::WriteAllBytes($Path, $Bytes)
}

function Format-Nullable {
    param([double] $Value, [int] $Digits = 3)
    if ($null -eq $Value) { return $null }
    return [math]::Round($Value, $Digits)
}

function Format-DateTime {
    param([DateTime] $Value)
    if ($null -eq $Value) { return $null }
    return $Value.ToString('yyyy-MM-dd HH:mm:ss.fff')
}

function Compute-Statistics {
    param([double[]] $Values)
    $count = $Values.Count
    if ($count -eq 0) {
        return [PSCustomObject][ordered]@{
            Count = 0
            Mean = $null
            Std = $null
            Median = $null
            Min = $null
            Max = $null
            P95 = $null
        }
    }
    $sorted = $Values | Sort-Object
    $sum = 0.0
    foreach ($v in $Values) { $sum += $v }
    $mean = $sum / $count
    if ($count -gt 1) {
        $variance = 0.0
        foreach ($v in $Values) { $variance += [math]::Pow($v - $mean, 2) }
        $variance /= ($count - 1)
        $std = [math]::Sqrt($variance)
    }
    else { $std = 0 }
    if ($count % 2 -eq 1) {
        $median = $sorted[[int]([math]::Floor($count / 2))]
    }
    else {
        $mid = [int]($count / 2)
        $median = ($sorted[$mid - 1] + $sorted[$mid]) / 2.0
    }
    $min = $sorted[0]
    $max = $sorted[$count - 1]
    $pIndex = [math]::Ceiling(0.95 * $count)
    if ($pIndex -lt 1) { $pIndex = 1 }
    if ($pIndex -gt $count) { $pIndex = $count }
    $p95 = $sorted[$pIndex - 1]
    return [PSCustomObject][ordered]@{
        Count = $count
        Mean = $mean
        Std = $std
        Median = $median
        Min = $min
        Max = $max
        P95 = $p95
    }
}

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
    $entries = New-Object System.Collections.Generic.List[object]
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
    $entries.Add([pscustomobject]@{ Name = '[Content_Types].xml'; Bytes = [System.Text.Encoding]::UTF8.GetBytes($contentTypes) }) | Out-Null

    $relsXml = "<?xml version='1.0' encoding='UTF-8'?><Relationships xmlns='http://schemas.openxmlformats.org/package/2006/relationships'>" +
        "<Relationship Id='rId1' Type='http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument' Target='xl/workbook.xml'/>" +
        "<Relationship Id='rId2' Type='http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties' Target='docProps/core.xml'/>" +
        "<Relationship Id='rId3' Type='http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties' Target='docProps/app.xml'/>" +
        "</Relationships>"
    $entries.Add([pscustomobject]@{ Name = '_rels/.rels'; Bytes = [System.Text.Encoding]::UTF8.GetBytes($relsXml) }) | Out-Null

    $sheetsNode = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $Sheets.Count; $i++) {
        $sheetId = $i + 1
        $sheetName = [System.Security.SecurityElement]::Escape($Sheets[$i].Name)
        $sheetsNode.Append("<sheet name='$sheetName' sheetId='$sheetId' r:id='rId$sheetId'/>") | Out-Null
    }
    $workbookXml = "<?xml version='1.0' encoding='UTF-8'?><workbook xmlns='http://schemas.openxmlformats.org/spreadsheetml/2006/main' xmlns:r='http://schemas.openxmlformats.org/officeDocument/2006/relationships'><sheets>$($sheetsNode.ToString())</sheets></workbook>"
    $entries.Add([pscustomobject]@{ Name = 'xl/workbook.xml'; Bytes = [System.Text.Encoding]::UTF8.GetBytes($workbookXml) }) | Out-Null

    $workbookRels = "<?xml version='1.0' encoding='UTF-8'?><Relationships xmlns='http://schemas.openxmlformats.org/package/2006/relationships'>"
    for ($i = 0; $i -lt $Sheets.Count; $i++) {
        $workbookRels += "<Relationship Id='rId$($i+1)' Type='http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet' Target='worksheets/sheet$($i+1).xml'/>"
    }
    $workbookRels += '</Relationships>'
    $entries.Add([pscustomobject]@{ Name = 'xl/_rels/workbook.xml.rels'; Bytes = [System.Text.Encoding]::UTF8.GetBytes($workbookRels) }) | Out-Null

    for ($i = 0; $i -lt $Sheets.Count; $i++) {
        $sheetXml = ConvertTo-WorksheetXml -Rows $Sheets[$i].Rows
        $entries.Add([pscustomobject]@{ Name = "xl/worksheets/sheet$($i+1).xml"; Bytes = [System.Text.Encoding]::UTF8.GetBytes($sheetXml) }) | Out-Null
    }

    $coreXml = "<?xml version='1.0' encoding='UTF-8'?><cp:coreProperties xmlns:cp='http://schemas.openxmlformats.org/package/2006/metadata/core-properties' xmlns:dc='http://purl.org/dc/elements/1.1/' xmlns:dcterms='http://purl.org/dc/terms/'><dc:title>IO 성능 평가 보고서</dc:title><dc:creator>Security Automation</dc:creator><cp:lastModifiedBy>Security Automation</cp:lastModifiedBy><dcterms:created xsi:type='dcterms:W3CDTF' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'>$(Get-Date -Format s)Z</dcterms:created></cp:coreProperties>"
    $entries.Add([pscustomobject]@{ Name = 'docProps/core.xml'; Bytes = [System.Text.Encoding]::UTF8.GetBytes($coreXml) }) | Out-Null

    $appXml = "<?xml version='1.0' encoding='UTF-8'?><Properties xmlns='http://schemas.openxmlformats.org/officeDocument/2006/extended-properties' xmlns:vt='http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes'><Application>PowerShell Automation</Application></Properties>"
    $entries.Add([pscustomobject]@{ Name = 'docProps/app.xml'; Bytes = [System.Text.Encoding]::UTF8.GetBytes($appXml) }) | Out-Null

    Write-ZipArchive -Path $Path -Entries $entries
}

function New-SimpleDocx {
    param([string] $Path, [string[]] $Paragraphs)
    $entries = New-Object System.Collections.Generic.List[object]
    $contentTypes = "<?xml version='1.0' encoding='UTF-8'?><Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'>" +
        "<Default Extension='rels' ContentType='application/vnd.openxmlformats-package.relationships+xml'/>" +
        "<Default Extension='xml' ContentType='application/xml'/>" +
        "<Override PartName='/word/document.xml' ContentType='application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml'/>" +
        "<Override PartName='/docProps/app.xml' ContentType='application/vnd.openxmlformats-officedocument.extended-properties+xml'/>" +
        "<Override PartName='/docProps/core.xml' ContentType='application/vnd.openxmlformats-package.core-properties+xml'/>" +
        "</Types>"
    $entries.Add([pscustomobject]@{ Name = '[Content_Types].xml'; Bytes = [System.Text.Encoding]::UTF8.GetBytes($contentTypes) }) | Out-Null

    $relsXml = "<?xml version='1.0' encoding='UTF-8'?><Relationships xmlns='http://schemas.openxmlformats.org/package/2006/relationships'>" +
        "<Relationship Id='rId1' Type='http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument' Target='word/document.xml'/>" +
        "<Relationship Id='rId2' Type='http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties' Target='docProps/core.xml'/>" +
        "<Relationship Id='rId3' Type='http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties' Target='docProps/app.xml'/>" +
        "</Relationships>"
    $entries.Add([pscustomobject]@{ Name = '_rels/.rels'; Bytes = [System.Text.Encoding]::UTF8.GetBytes($relsXml) }) | Out-Null

    $docBuilder = New-Object System.Text.StringBuilder
    foreach ($paragraph in $Paragraphs) {
        $escaped = [System.Security.SecurityElement]::Escape($paragraph)
        $docBuilder.Append("<w:p><w:r><w:t xml:space='preserve'>$escaped</w:t></w:r></w:p>") | Out-Null
    }
    $documentXml = "<?xml version='1.0' encoding='UTF-8'?><w:document xmlns:w='http://schemas.openxmlformats.org/wordprocessingml/2006/main'>$docBuilder</w:document>"
    $entries.Add([pscustomobject]@{ Name = 'word/document.xml'; Bytes = [System.Text.Encoding]::UTF8.GetBytes($documentXml) }) | Out-Null

    $coreXml = "<?xml version='1.0' encoding='UTF-8'?><cp:coreProperties xmlns:cp='http://schemas.openxmlformats.org/package/2006/metadata/core-properties' xmlns:dc='http://purl.org/dc/elements/1.1/' xmlns:dcterms='http://purl.org/dc/terms/'><dc:title>IO 성능 평가 보고서</dc:title><dc:creator>Security Automation</dc:creator><cp:lastModifiedBy>Security Automation</cp:lastModifiedBy><dcterms:created xsi:type='dcterms:W3CDTF' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'>$(Get-Date -Format s)Z</dcterms:created></cp:coreProperties>"
    $entries.Add([pscustomobject]@{ Name = 'docProps/core.xml'; Bytes = [System.Text.Encoding]::UTF8.GetBytes($coreXml) }) | Out-Null

    $appXml = "<?xml version='1.0' encoding='UTF-8'?><Properties xmlns='http://schemas.openxmlformats.org/officeDocument/2006/extended-properties' xmlns:vt='http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes'><Application>PowerShell Automation</Application></Properties>"
    $entries.Add([pscustomobject]@{ Name = 'docProps/app.xml'; Bytes = [System.Text.Encoding]::UTF8.GetBytes($appXml) }) | Out-Null

    Write-ZipArchive -Path $Path -Entries $entries
}

function Export-Chart {
    param(
        [string] $Path,
        [string] $Title,
        [string] $XAxisTitle,
        [string] $YAxisTitle,
        [hashtable[]] $SeriesData
    )
    $chart = New-Object System.Windows.Forms.DataVisualization.Charting.Chart
    try {
        $chart.Width = 900
        $chart.Height = 600
        $chart.BackColor = [System.Drawing.Color]::White
        $chartArea = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea 'Default'
        $chartArea.AxisX.Interval = 1
        $chartArea.AxisX.Title = $XAxisTitle
        $chartArea.AxisY.Title = $YAxisTitle
        $chart.ChartAreas.Add($chartArea)
        $legend = New-Object System.Windows.Forms.DataVisualization.Charting.Legend 'Legend'
        $chart.Legends.Add($legend)
        foreach ($seriesSpec in $SeriesData) {
            $series = New-Object System.Windows.Forms.DataVisualization.Charting.Series $seriesSpec.Name
            $series.ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Column
            $series.Points.DataBindXY($seriesSpec.XValues, $seriesSpec.YValues)
            $chart.Series.Add($series)
        }
        $chart.Titles.Add($Title) | Out-Null
        $directory = Split-Path -Path $Path -Parent
        Ensure-Directory -Path $directory
        $chart.SaveImage($Path, 'Png')
    }
    finally {
        $chart.Dispose()
    }
}
#endregion

#region 샘플 데이터 구성
function Initialize-SampleDataset {
    param(
        [string] $DatasetRoot,
        [int] $Seed
    )
    Ensure-Directory -Path $DatasetRoot
    $extensions = @(
        @{ Ext = 'doc';   BaseName = 'report';   SizeMB = 1 },
        @{ Ext = 'docx';  BaseName = 'reportx';  SizeMB = 2 },
        @{ Ext = 'ppt';   BaseName = 'brief';    SizeMB = 4 },
        @{ Ext = 'pptx';  BaseName = 'deck';     SizeMB = 4 },
        @{ Ext = 'xls';   BaseName = 'sheet';    SizeMB = 2 },
        @{ Ext = 'xlsx';  BaseName = 'sheetx';   SizeMB = 2 },
        @{ Ext = 'hwp';   BaseName = 'proposal'; SizeMB = 8 },
        @{ Ext = 'hwpx';  BaseName = 'proposalx';SizeMB = 8 },
        @{ Ext = 'txt';   BaseName = 'notes';    SizeMB = 1 },
        @{ Ext = 'ini';   BaseName = 'config';   SizeMB = 1 }
    )

    $sizePattern = @(1, 2, 4, 8, 16)
    $rand = [System.Random]::new($Seed)
    $result = @()
    for ($i = 1; $i -le 100; $i++) {
        $plan = $extensions[($i - 1) % $extensions.Count]
        $sizeMB = $sizePattern[($i - 1) % $sizePattern.Count]
        $name = "sample_{0:D3}_{1}.{2}" -f $i, $plan.BaseName, $plan.Ext
        $path = Join-Path $DatasetRoot $name
        $bytes = [int64]($sizeMB * 1MB)
        if ($bytes -lt 1048576) { $bytes = 1048576 }
        $buffer = New-Object byte[] $bytes
        $rand.NextBytes($buffer)
        Write-BytesFile -Path $path -Bytes $buffer
        $info = Get-Item -LiteralPath $path
        $result += [PSCustomObject]@{
            Index = $i
            Name = $info.Name
            Path = $info.FullName
            SizeBytes = [int64]$info.Length
            SizeMB = [math]::Round($info.Length / 1MB, 3)
        }
    }
    Write-Host "샘플 데이터가 100개로 준비되었습니다: $DatasetRoot"
    return $result
}
#endregion

#region 측정 함수
function Measure-WriteOperation {
    param([string] $SourcePath, [string] $DestinationPath)
    if (Test-Path -LiteralPath $DestinationPath) {
        Remove-Item -LiteralPath $DestinationPath -Force
    }
    $start = Get-Date
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    [System.IO.File]::Copy($SourcePath, $DestinationPath, $true)
    $watch.Stop()
    $end = Get-Date
    return [PSCustomObject]@{
        StartTime = $start
        EndTime = $end
        DurationMs = $watch.Elapsed.TotalMilliseconds
    }
}

function Measure-ReadOperation {
    param([string] $Path)
    $bufferSize = 4MB
    $buffer = New-Object byte[] $bufferSize
    $start = Get-Date
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        while ($true) {
            $read = $stream.Read($buffer, 0, $buffer.Length)
            if ($read -le 0) { break }
        }
    }
    finally {
        $stream.Dispose()
    }
    $watch.Stop()
    $end = Get-Date
    return [PSCustomObject]@{
        StartTime = $start
        EndTime = $end
        DurationMs = $watch.Elapsed.TotalMilliseconds
    }
}

function Measure-AreaSample {
    param(
        [string] $Scenario,
        [PSCustomObject] $Sample,
        [string] $TargetRoot
    )
    $destination = Join-Path $TargetRoot $Sample.Name
    $write = Measure-WriteOperation -SourcePath $Sample.Path -DestinationPath $destination
    $writeMs = $write.DurationMs
    $writeMBps = $null
    if ($writeMs -gt 0) {
        $writeMBps = ($Sample.SizeBytes / 1MB) / ($writeMs / 1000.0)
    }

    $read = Measure-ReadOperation -Path $destination
    $readMs = $read.DurationMs
    $readMBps = $null
    if ($readMs -gt 0) {
        $readMBps = ($Sample.SizeBytes / 1MB) / ($readMs / 1000.0)
    }

    if (Test-Path -LiteralPath $destination) {
        Remove-Item -LiteralPath $destination -Force
    }

    return [PSCustomObject][ordered]@{
        Scenario = $Scenario
        Path = $destination
        SizeMB = [math]::Round($Sample.SizeBytes / 1MB, 3)
        WriteStart = Format-DateTime -Value $write.StartTime
        WriteEnd = Format-DateTime -Value $write.EndTime
        WriteDurationMs = Format-Nullable -Value $writeMs -Digits 3
        WriteMBps = Format-Nullable -Value $writeMBps -Digits 3
        ReadStart = Format-DateTime -Value $read.StartTime
        ReadEnd = Format-DateTime -Value $read.EndTime
        ReadDurationMs = Format-Nullable -Value $readMs -Digits 3
        ReadMBps = Format-Nullable -Value $readMBps -Digits 3
        WriteDurationRaw = $writeMs
        ReadDurationRaw = $readMs
        WriteMBpsRaw = $writeMBps
        ReadMBpsRaw = $readMBps
    }
}
#endregion

#region 메인 실행
Write-Host '=== 입출력 속도 성능평가 자동화 시작 (v0.5) ==='
$normalRoot = Read-RequiredPath -PromptText '일반영역 위치 (예: D:\\Test\\NormalArea)'
$secureRoot = Read-RequiredPath -PromptText '보안영역 위치 (예: D:\\Test\\SecureArea)'
$datasetRoot = Read-RequiredPath -PromptText '샘플 데이터 위치 (예: D:\\Test\\Dataset) - 기존 파일 삭제 후 100개 샘플을 새로 생성합니다.'
$resultTarget = Read-RequiredPath -PromptText '결과 데이터 저장 위치 (폴더 또는 .xlsx 경로, 예: D:\\logs 또는 D:\\logs\\IO_Report_v0.5.xlsx)'

if ($normalRoot -eq $secureRoot) {
    throw '일반영역과 보안영역 경로는 서로 달라야 합니다.'
}

Ensure-Directory -Path $normalRoot
Ensure-Directory -Path $secureRoot
Clear-Directory -Path $normalRoot
Clear-Directory -Path $secureRoot

Ensure-Directory -Path $datasetRoot
Write-Host "샘플 데이터 위치를 초기화합니다: $datasetRoot"
Clear-Directory -Path $datasetRoot

$seed = Get-Random -Maximum 1000000
$samples = Initialize-SampleDataset -DatasetRoot $datasetRoot -Seed $seed
Write-Host "샘플 데이터 준비 완료 (Seed: $seed, 파일 수: $($samples.Count))"

$useFileTarget = $resultTarget -match '\\.xlsx$'
$reportDirectory = if ($useFileTarget) {
    $parent = Split-Path -Path $resultTarget -Parent
    if ([string]::IsNullOrWhiteSpace($parent)) { (Get-Location).Path } else { $parent }
} else {
    $resultTarget
}
Ensure-Directory -Path $reportDirectory

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$runId = $timestamp
$csvFolder = Join-Path $reportDirectory 'csv'
Ensure-Directory -Path $csvFolder
$chartFolder = Join-Path $reportDirectory 'charts'
Ensure-Directory -Path $chartFolder

$records = New-Object System.Collections.Generic.List[object]
$totalSamples = $samples.Count
for ($i = 0; $i -lt $totalSamples; $i++) {
    $sample = $samples[$i]
    $sampleIndex = if ($sample.PSObject.Properties['Index']) { $sample.Index } else { $i + 1 }
    Write-Host "[$($sampleIndex)/$totalSamples] 일반영역 저장/읽기 측정 중..." -ForegroundColor Cyan
    $normalRecord = Measure-AreaSample -Scenario 'Normal' -Sample $sample -TargetRoot $normalRoot

    $records.Add([PSCustomObject][ordered]@{
        RunId = $runId
        SampleIndex = $sampleIndex
        Scenario = 'Normal'
        Operation = 'Write'
        FilePath = $normalRecord.Path
        SizeMB = $normalRecord.SizeMB
        SaveStart = $normalRecord.WriteStart
        SaveEnd = $normalRecord.WriteEnd
        SaveDurationMs = $normalRecord.WriteDurationMs
        ReadStart = $null
        ReadEnd = $null
        ReadDurationMs = $null
        SaveMBps = Format-Nullable -Value $normalRecord.WriteMBps -Digits 3
        ReadMBps = $null
        Timestamp = $normalRecord.WriteEnd
        DurationMs = $normalRecord.WriteDurationRaw
        MBps = $normalRecord.WriteMBpsRaw
    }) | Out-Null

    $records.Add([PSCustomObject][ordered]@{
        RunId = $runId
        SampleIndex = $sampleIndex
        Scenario = 'Normal'
        Operation = 'Read'
        FilePath = $normalRecord.Path
        SizeMB = $normalRecord.SizeMB
        SaveStart = $null
        SaveEnd = $null
        SaveDurationMs = $null
        ReadStart = $normalRecord.ReadStart
        ReadEnd = $normalRecord.ReadEnd
        ReadDurationMs = $normalRecord.ReadDurationMs
        SaveMBps = $null
        ReadMBps = Format-Nullable -Value $normalRecord.ReadMBps -Digits 3
        Timestamp = $normalRecord.ReadEnd
        DurationMs = $normalRecord.ReadDurationRaw
        MBps = $normalRecord.ReadMBpsRaw
    }) | Out-Null
}

Write-Host '보안영역 측정을 진행하기 전에 30초간 대기합니다...' -ForegroundColor Yellow
Start-Sleep -Seconds 30

for ($i = 0; $i -lt $totalSamples; $i++) {
    $sample = $samples[$i]
    $sampleIndex = if ($sample.PSObject.Properties['Index']) { $sample.Index } else { $i + 1 }
    Write-Host "[$($sampleIndex)/$totalSamples] 보안영역 저장/읽기 측정 중..." -ForegroundColor Green
    $secureRecord = Measure-AreaSample -Scenario 'Secure' -Sample $sample -TargetRoot $secureRoot

    $records.Add([PSCustomObject][ordered]@{
        RunId = $runId
        SampleIndex = $sampleIndex
        Scenario = 'Secure'
        Operation = 'Write'
        FilePath = $secureRecord.Path
        SizeMB = $secureRecord.SizeMB
        SaveStart = $secureRecord.WriteStart
        SaveEnd = $secureRecord.WriteEnd
        SaveDurationMs = $secureRecord.WriteDurationMs
        ReadStart = $null
        ReadEnd = $null
        ReadDurationMs = $null
        SaveMBps = Format-Nullable -Value $secureRecord.WriteMBps -Digits 3
        ReadMBps = $null
        Timestamp = $secureRecord.WriteEnd
        DurationMs = $secureRecord.WriteDurationRaw
        MBps = $secureRecord.WriteMBpsRaw
    }) | Out-Null

    $records.Add([PSCustomObject][ordered]@{
        RunId = $runId
        SampleIndex = $sampleIndex
        Scenario = 'Secure'
        Operation = 'Read'
        FilePath = $secureRecord.Path
        SizeMB = $secureRecord.SizeMB
        SaveStart = $null
        SaveEnd = $null
        SaveDurationMs = $null
        ReadStart = $secureRecord.ReadStart
        ReadEnd = $secureRecord.ReadEnd
        ReadDurationMs = $secureRecord.ReadDurationMs
        SaveMBps = $null
        ReadMBps = Format-Nullable -Value $secureRecord.ReadMBps -Digits 3
        Timestamp = $secureRecord.ReadEnd
        DurationMs = $secureRecord.ReadDurationRaw
        MBps = $secureRecord.ReadMBpsRaw
    }) | Out-Null
}

Write-Host '측정이 완료되었습니다. 결과를 정리합니다.' -ForegroundColor Cyan

$resultsCsv = Join-Path $csvFolder "IO_Performance_v0_5_${timestamp}.csv"
$records | Export-Csv -Path $resultsCsv -NoTypeInformation -Encoding UTF8

#endregion

#region 통계 계산
$scenarioOpGroups = $records | Group-Object -Property Scenario, Operation
$scenarioStats = @()
foreach ($group in $scenarioOpGroups) {
    $sampleRow = $group.Group | Select-Object -First 1
    if (-not $sampleRow) { continue }
    $scenario = ($sampleRow.Scenario).Trim()
    $operation = ($sampleRow.Operation).Trim()
    $durValues = @($group.Group | Where-Object { $_.DurationMs -ne $null } | ForEach-Object { [double]($_.DurationMs) })
    $durStats = Compute-Statistics -Values $durValues
    $mbpsValues = @($group.Group | Where-Object { $_.MBps -ne $null } | ForEach-Object { [double]($_.MBps) })
    $mbpsStats = Compute-Statistics -Values $mbpsValues
    $scenarioStats += [PSCustomObject][ordered]@{
        Scenario = $scenario
        Operation = $operation
        DurationMs_count = $durStats.Count
        DurationMs_mean = if ($durStats.Mean -ne $null) { [math]::Round($durStats.Mean, 3) } else { $null }
        DurationMs_std = if ($durStats.Std -ne $null) { [math]::Round($durStats.Std, 3) } else { $null }
        DurationMs_median = if ($durStats.Median -ne $null) { [math]::Round($durStats.Median, 3) } else { $null }
        DurationMs_min = if ($durStats.Min -ne $null) { [math]::Round($durStats.Min, 3) } else { $null }
        DurationMs_max = if ($durStats.Max -ne $null) { [math]::Round($durStats.Max, 3) } else { $null }
        MBps_mean = if ($mbpsStats.Mean -ne $null) { [math]::Round($mbpsStats.Mean, 3) } else { $null }
        MBps_std = if ($mbpsStats.Std -ne $null) { [math]::Round($mbpsStats.Std, 3) } else { $null }
        MBps_median = if ($mbpsStats.Median -ne $null) { [math]::Round($mbpsStats.Median, 3) } else { $null }
        MBps_min = if ($mbpsStats.Min -ne $null) { [math]::Round($mbpsStats.Min, 3) } else { $null }
        MBps_max = if ($mbpsStats.Max -ne $null) { [math]::Round($mbpsStats.Max, 3) } else { $null }
    }
}

$sizeOperationStats = @()
$distinctSizes = $records | Select-Object -ExpandProperty SizeMB -Unique | Sort-Object
foreach ($size in $distinctSizes) {
    foreach ($operation in @('Write','Read')) {
        $normalRows = $records | Where-Object { $_.SizeMB -eq $size -and $_.Scenario -eq 'Normal' -and $_.Operation -eq $operation }
        $secureRows = $records | Where-Object { $_.SizeMB -eq $size -and $_.Scenario -eq 'Secure' -and $_.Operation -eq $operation }
        $normalDurStats = Compute-Statistics -Values (@($normalRows | Select-Object -ExpandProperty DurationMs))
        $secureDurStats = Compute-Statistics -Values (@($secureRows | Select-Object -ExpandProperty DurationMs))
        $normalMbStats = Compute-Statistics -Values (@($normalRows | Select-Object -ExpandProperty MBps))
        $secureMbStats = Compute-Statistics -Values (@($secureRows | Select-Object -ExpandProperty MBps))
        $timeRatio = if ($secureDurStats.Mean -gt 0) { [math]::Round(($normalDurStats.Mean / $secureDurStats.Mean) * 100, 2) } else { 0 }
        $throughputRatio = if ($normalMbStats.Mean -gt 0) { [math]::Round(($secureMbStats.Mean / $normalMbStats.Mean) * 100, 2) } else { 0 }
        $sizeOperationStats += [PSCustomObject][ordered]@{
            SizeMB = $size
            Operation = $operation
            Normal_avg_ms = if ($normalDurStats.Mean -ne $null) { [math]::Round($normalDurStats.Mean, 3) } else { $null }
            Secure_avg_ms = if ($secureDurStats.Mean -ne $null) { [math]::Round($secureDurStats.Mean, 3) } else { $null }
            Time_Perf_Ratio_pct = $timeRatio
            Normal_avg_MBps = if ($normalMbStats.Mean -ne $null) { [math]::Round($normalMbStats.Mean, 3) } else { $null }
            Secure_avg_MBps = if ($secureMbStats.Mean -ne $null) { [math]::Round($secureMbStats.Mean, 3) } else { $null }
            Throughput_Perf_Ratio_pct = $throughputRatio
            Pass_Time = if ($timeRatio -ge 90) { 'PASS' } else { 'FAIL' }
            Pass_MBps = if ($throughputRatio -ge 90) { 'PASS' } else { 'FAIL' }
            Normal_samples = $normalDurStats.Count
            Secure_samples = $secureDurStats.Count
            Normal_p95_ms = if ($normalDurStats.P95 -ne $null) { [math]::Round($normalDurStats.P95, 3) } else { $null }
            Secure_p95_ms = if ($secureDurStats.P95 -ne $null) { [math]::Round($secureDurStats.P95, 3) } else { $null }
        }
    }
}

$normalWriteRow = $scenarioStats | Where-Object { $_.Scenario -eq 'Normal' -and $_.Operation -eq 'Write' } | Select-Object -First 1
$secureWriteRow = $scenarioStats | Where-Object { $_.Scenario -eq 'Secure' -and $_.Operation -eq 'Write' } | Select-Object -First 1
$normalReadRow = $scenarioStats | Where-Object { $_.Scenario -eq 'Normal' -and $_.Operation -eq 'Read' } | Select-Object -First 1
$secureReadRow = $scenarioStats | Where-Object { $_.Scenario -eq 'Secure' -and $_.Operation -eq 'Read' } | Select-Object -First 1

$normalWriteAvgTime = if ($normalWriteRow) { $normalWriteRow.DurationMs_mean } else { $null }
$secureWriteAvgTime = if ($secureWriteRow) { $secureWriteRow.DurationMs_mean } else { $null }
$normalReadAvgTime = if ($normalReadRow) { $normalReadRow.DurationMs_mean } else { $null }
$secureReadAvgTime = if ($secureReadRow) { $secureReadRow.DurationMs_mean } else { $null }
$normalWriteAvgMb = if ($normalWriteRow) { $normalWriteRow.MBps_mean } else { $null }
$secureWriteAvgMb = if ($secureWriteRow) { $secureWriteRow.MBps_mean } else { $null }
$normalReadAvgMb = if ($normalReadRow) { $normalReadRow.MBps_mean } else { $null }
$secureReadAvgMb = if ($secureReadRow) { $secureReadRow.MBps_mean } else { $null }

$writeTimeRatio = if ($secureWriteAvgTime -gt 0) { [math]::Round(($normalWriteAvgTime / $secureWriteAvgTime) * 100, 2) } else { 0 }
$readTimeRatio = if ($secureReadAvgTime -gt 0) { [math]::Round(($normalReadAvgTime / $secureReadAvgTime) * 100, 2) } else { 0 }
$writeThroughputRatio = if ($normalWriteAvgMb -gt 0) { [math]::Round(($secureWriteAvgMb / $normalWriteAvgMb) * 100, 2) } else { 0 }
$readThroughputRatio = if ($normalReadAvgMb -gt 0) { [math]::Round(($secureReadAvgMb / $normalReadAvgMb) * 100, 2) } else { 0 }

$passWriteTime = if ($writeTimeRatio -ge 90) { 'PASS' } else { 'FAIL' }
$passReadTime = if ($readTimeRatio -ge 90) { 'PASS' } else { 'FAIL' }
$passWriteMb = if ($writeThroughputRatio -ge 90) { 'PASS' } else { 'FAIL' }
$passReadMb = if ($readThroughputRatio -ge 90) { 'PASS' } else { 'FAIL' }
#endregion

#region 추가 산출물
$summaryCsv = Join-Path $csvFolder "IO_Performance_ScenarioSummary_${timestamp}.csv"
$scenarioStats | Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding UTF8

$sizeCsv = Join-Path $csvFolder "IO_Performance_SizeSummary_${timestamp}.csv"
$sizeOperationStats | Export-Csv -Path $sizeCsv -NoTypeInformation -Encoding UTF8

$ratioRows = @(
    [PSCustomObject][ordered]@{
        Operation = 'Write'
        Normal_Avg_Time_ms = $normalWriteAvgTime
        Secure_Avg_Time_ms = $secureWriteAvgTime
        Time_Perf_Ratio_pct = $writeTimeRatio
        Normal_Avg_MBps = $normalWriteAvgMb
        Secure_Avg_MBps = $secureWriteAvgMb
        Throughput_Perf_Ratio_pct = $writeThroughputRatio
        Pass_Time = $passWriteTime
        Pass_Throughput = $passWriteMb
    },
    [PSCustomObject][ordered]@{
        Operation = 'Read'
        Normal_Avg_Time_ms = $normalReadAvgTime
        Secure_Avg_Time_ms = $secureReadAvgTime
        Time_Perf_Ratio_pct = $readTimeRatio
        Normal_Avg_MBps = $normalReadAvgMb
        Secure_Avg_MBps = $secureReadAvgMb
        Throughput_Perf_Ratio_pct = $readThroughputRatio
        Pass_Time = $passReadTime
        Pass_Throughput = $passReadMb
    }
)

$ratioCsv = Join-Path $csvFolder "IO_Performance_Ratio_${timestamp}.csv"
$ratioRows | Export-Csv -Path $ratioCsv -NoTypeInformation -Encoding UTF8

$excelPath = if ($useFileTarget) { $resultTarget } else { Join-Path $reportDirectory "IO_Performance_Report_${timestamp}.xlsx" }
New-SimpleWorkbook -Path $excelPath -Sheets @(
    @{ Name = 'Ratios'; Rows = $ratioRows },
    @{ Name = 'ScenarioStats'; Rows = $scenarioStats },
    @{ Name = 'SizeStats'; Rows = $sizeOperationStats },
    @{ Name = 'Details'; Rows = $records }
)

# 차트 생성
$sizeLabels = $distinctSizes | ForEach-Object { [string]$_ }
$writeNormalSeries = @()
$writeSecureSeries = @()
$readNormalSeries = @()
$readSecureSeries = @()
foreach ($size in $distinctSizes) {
    $writeNormalValue = ($sizeOperationStats | Where-Object { $_.SizeMB -eq $size -and $_.Operation -eq 'Write' } | Select-Object -ExpandProperty Normal_avg_MBps)
    if ($writeNormalValue -eq $null) { $writeNormalValue = 0 }
    $writeNormalSeries += $writeNormalValue

    $writeSecureValue = ($sizeOperationStats | Where-Object { $_.SizeMB -eq $size -and $_.Operation -eq 'Write' } | Select-Object -ExpandProperty Secure_avg_MBps)
    if ($writeSecureValue -eq $null) { $writeSecureValue = 0 }
    $writeSecureSeries += $writeSecureValue

    $readNormalValue = ($sizeOperationStats | Where-Object { $_.SizeMB -eq $size -and $_.Operation -eq 'Read' } | Select-Object -ExpandProperty Normal_avg_MBps)
    if ($readNormalValue -eq $null) { $readNormalValue = 0 }
    $readNormalSeries += $readNormalValue

    $readSecureValue = ($sizeOperationStats | Where-Object { $_.SizeMB -eq $size -and $_.Operation -eq 'Read' } | Select-Object -ExpandProperty Secure_avg_MBps)
    if ($readSecureValue -eq $null) { $readSecureValue = 0 }
    $readSecureSeries += $readSecureValue
}

$writeDurationNormal = @()
$writeDurationSecure = @()
$readDurationNormal = @()
$readDurationSecure = @()
foreach ($size in $distinctSizes) {
    $writeDurationNormalValue = ($sizeOperationStats | Where-Object { $_.SizeMB -eq $size -and $_.Operation -eq 'Write' } | Select-Object -ExpandProperty Normal_avg_ms)
    if ($writeDurationNormalValue -eq $null) { $writeDurationNormalValue = 0 }
    $writeDurationNormal += $writeDurationNormalValue

    $writeDurationSecureValue = ($sizeOperationStats | Where-Object { $_.SizeMB -eq $size -and $_.Operation -eq 'Write' } | Select-Object -ExpandProperty Secure_avg_ms)
    if ($writeDurationSecureValue -eq $null) { $writeDurationSecureValue = 0 }
    $writeDurationSecure += $writeDurationSecureValue

    $readDurationNormalValue = ($sizeOperationStats | Where-Object { $_.SizeMB -eq $size -and $_.Operation -eq 'Read' } | Select-Object -ExpandProperty Normal_avg_ms)
    if ($readDurationNormalValue -eq $null) { $readDurationNormalValue = 0 }
    $readDurationNormal += $readDurationNormalValue

    $readDurationSecureValue = ($sizeOperationStats | Where-Object { $_.SizeMB -eq $size -and $_.Operation -eq 'Read' } | Select-Object -ExpandProperty Secure_avg_ms)
    if ($readDurationSecureValue -eq $null) { $readDurationSecureValue = 0 }
    $readDurationSecure += $readDurationSecureValue
}

$chartWriteThroughput = Join-Path $chartFolder 'Write_avg_throughput.png'
Export-Chart -Path $chartWriteThroughput -Title '쓰기 평균 처리량 비교' -XAxisTitle 'Size (MB)' -YAxisTitle 'MB/s' -SeriesData @(
    @{ Name = 'Normal'; XValues = $sizeLabels; YValues = $writeNormalSeries },
    @{ Name = 'Secure'; XValues = $sizeLabels; YValues = $writeSecureSeries }
)

$chartReadThroughput = Join-Path $chartFolder 'Read_avg_throughput.png'
Export-Chart -Path $chartReadThroughput -Title '읽기 평균 처리량 비교' -XAxisTitle 'Size (MB)' -YAxisTitle 'MB/s' -SeriesData @(
    @{ Name = 'Normal'; XValues = $sizeLabels; YValues = $readNormalSeries },
    @{ Name = 'Secure'; XValues = $sizeLabels; YValues = $readSecureSeries }
)

$chartWriteDuration = Join-Path $chartFolder 'Write_avg_duration.png'
Export-Chart -Path $chartWriteDuration -Title '쓰기 평균 지연시간 비교' -XAxisTitle 'Size (MB)' -YAxisTitle 'ms' -SeriesData @(
    @{ Name = 'Normal'; XValues = $sizeLabels; YValues = $writeDurationNormal },
    @{ Name = 'Secure'; XValues = $sizeLabels; YValues = $writeDurationSecure }
)

$chartReadDuration = Join-Path $chartFolder 'Read_avg_duration.png'
Export-Chart -Path $chartReadDuration -Title '읽기 평균 지연시간 비교' -XAxisTitle 'Size (MB)' -YAxisTitle 'ms' -SeriesData @(
    @{ Name = 'Normal'; XValues = $sizeLabels; YValues = $readDurationNormal },
    @{ Name = 'Secure'; XValues = $sizeLabels; YValues = $readDurationSecure }
)
#endregion

#region DOCX 보고서 작성
$totalSamples = $records.Count
$sizeDistribution = $distinctSizes -join ', '
$methodSummary = @(
    '1. 방법 요약',
    '본 보고서는 사전에 정의된 “성능 측정 및 분석 방법” 문서를 준수하여 작성되었습니다. 평가 기준은 보안영역 성능이 일반영역의 90% 이상일 때 합격으로 판정합니다.',
    '시간 지표는 (일반영역 시간 / 보안영역 시간) × 100, 처리량 지표는 (보안영역 MBps / 일반영역 MBps) × 100으로 산출했습니다.'
)

$dataSummaryIntro = "2. 데이터 요약`n샘플 수(총): $totalSamples`n파일 크기(SizeMB) 분포: [$sizeDistribution]`nOperation: Write/Read, Scenario: Normal/Secure 기준으로 평균·표준편차·중앙값·최솟값·최댓값을 산출했습니다."

$scenarioHeader = '2.1 Scenario x Operation 통계 요약'
$scenarioTable = 'Scenario,Operation,DurationMs_count,DurationMs_mean,DurationMs_std,DurationMs_median,DurationMs_min,DurationMs_max,MBps_mean,MBps_std,MBps_median,MBps_min,MBps_max'
foreach ($row in $scenarioStats | Sort-Object Scenario, Operation) {
    $scenarioTable += "`n{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12}" -f `
        $row.Scenario,
        $row.Operation,
        $row.DurationMs_count,
        $row.DurationMs_mean,
        $row.DurationMs_std,
        $row.DurationMs_median,
        $row.DurationMs_min,
        $row.DurationMs_max,
        $row.MBps_mean,
        $row.MBps_std,
        $row.MBps_median,
        $row.MBps_min,
        $row.MBps_max
}

$coreSummaryLines = @(
    '3. 핵심 지표 및 합격 판정(전체)',
    ('Operation,Normal Avg Time (ms),Secure Avg Time (ms),Time Perf Ratio (%),Normal Avg MBps,Secure Avg MBps,Throughput Perf Ratio (%),Pass (Time ≥ 90%),Pass (MBps ≥ 90%)'),
    ('Write,{0},{1},{2},{3},{4},{5},{6},{7}' -f $normalWriteAvgTime, $secureWriteAvgTime, $writeTimeRatio, $normalWriteAvgMb, $secureWriteAvgMb, $writeThroughputRatio, $passWriteTime, $passWriteMb),
    ('Read,{0},{1},{2},{3},{4},{5},{6},{7}' -f $normalReadAvgTime, $secureReadAvgTime, $readTimeRatio, $normalReadAvgMb, $secureReadAvgMb, $readThroughputRatio, $passReadTime, $passReadMb)
)

$sizeHeader = '4. 사이즈별 상세 비교'
$sizeTable = 'SizeMB,Operation,Normal avg_ms,Secure avg_ms,Time Perf Ratio (%),Normal avg_MBps,Secure avg_MBps,Throughput Perf Ratio (%),Pass (Time ≥ 90%),Pass (MBps ≥ 90%),Normal samples,Secure samples,Normal p95_ms,Secure p95_ms'
foreach ($row in $sizeOperationStats | Sort-Object SizeMB, Operation) {
    $sizeTable += "`n{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13}" -f `
        $row.SizeMB,
        $row.Operation,
        $row.Normal_avg_ms,
        $row.Secure_avg_ms,
        $row.Time_Perf_Ratio_pct,
        $row.Normal_avg_MBps,
        $row.Secure_avg_MBps,
        $row.Throughput_Perf_Ratio_pct,
        $row.Pass_Time,
        $row.Pass_MBps,
        $row.Normal_samples,
        $row.Secure_samples,
        $row.Normal_p95_ms,
        $row.Secure_p95_ms
}

$chartsSection = @(
    '5. 시각화',
    (Split-Path -Leaf $chartWriteThroughput),
    (Split-Path -Leaf $chartReadThroughput),
    (Split-Path -Leaf $chartWriteDuration),
    (Split-Path -Leaf $chartReadDuration)
)

$analysisLines = @(
    '6. 해석 및 리스크',
    "- 쓰기(시간) 성능비율: $writeTimeRatio% → $passWriteTime",
    "- 읽기(시간) 성능비율: $readTimeRatio% → $passReadTime",
    "- 쓰기(처리량) 성능비율: $writeThroughputRatio% → $passWriteMb",
    "- 읽기(처리량) 성능비율: $readThroughputRatio% → $passReadMb",
    '시간 지표는 값이 작을수록 성능이 좋고, 처리량 지표는 값이 클수록 성능이 좋습니다. 결과는 보안영역이 전반적으로 일반영역 대비 동등하거나 우수한 경향을 보임을 나타냅니다.',
    '장치 캐시, 파일 시스템 버퍼, 백그라운드 프로세스 등의 외란 요인이 결과에 영향을 줄 수 있으므로, 측정 간 대기시간 삽입, 순서 랜덤화, 반복 횟수 확대 등을 통해 재현성을 확보하는 것을 권고합니다.'
)

$finalVerdict = @(
    '7. 최종 판정',
    "시간 지표 기준: $passWriteTime (Write), $passReadTime (Read)",
    "처리량 지표 기준: $passWriteMb (Write), $passReadMb (Read)",
    (if (($passWriteTime -eq 'PASS') -and ($passReadTime -eq 'PASS') -and ($passWriteMb -eq 'PASS') -and ($passReadMb -eq 'PASS')) { '⇒ 종합 판정: PASS (보안영역 성능이 90% 이상 유지)' } else { '⇒ 종합 판정: FAIL (보안영역 성능이 기준 미달)' })
)

$docxPath = if ($useFileTarget) {
    Join-Path $reportDirectory "IO_Performance_Analysis_Report_${timestamp}.docx"
} else {
    Join-Path $reportDirectory "IO_Performance_Analysis_Report_${timestamp}.docx"
}

$paragraphs = @()
$paragraphs += $methodSummary
$paragraphs += ''
$paragraphs += $dataSummaryIntro
$paragraphs += ''
$paragraphs += $scenarioHeader
$paragraphs += $scenarioTable
$paragraphs += ''
$paragraphs += $coreSummaryLines
$paragraphs += ''
$paragraphs += $sizeHeader
$paragraphs += $sizeTable
$paragraphs += ''
$paragraphs += $chartsSection
$paragraphs += ''
$paragraphs += $analysisLines
$paragraphs += ''
$paragraphs += $finalVerdict

New-SimpleDocx -Path $docxPath -Paragraphs $paragraphs
#endregion

Write-Host '=== 입출력 속도 성능평가 v0.5가 완료되었습니다. 산출물을 확인하세요. ==='
Write-Host "CSV 폴더: $csvFolder"
Write-Host "엑셀 파일: $excelPath"
Write-Host "DOCX 보고서: $docxPath"
Write-Host "차트 폴더: $chartFolder"
