<#
    파일 생성 자동화 스크립트
    - 일반영역/보안영역 경로를 입력받아 기존 내용을 모두 정리합니다.
    - 평가용 폴더(Docs, SysCfg)를 만들고 요구된 샘플 파일을 새로 생성합니다.
    - 난수 시드를 활용해 문서 크기를 무작위로 선택하며, 사용된 시드는 화면에 안내합니다.
#>

[CmdletBinding()]
param()

function Read-PathPrompt {
    param(
        [Parameter(Mandatory)] [string] $PromptText
    )
    while ($true) {
        $value = Read-Host -Prompt $PromptText
        if ([string]::IsNullOrWhiteSpace($value)) {
            Write-Host "경로를 입력해야 합니다. 다시 입력해 주세요." -ForegroundColor Yellow
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
            Write-Host "삭제하지 못한 항목이 있습니다: $($_.FullName) - $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

function Write-BytesFile {
    param(
        [string] $Path,
        [byte[]] $Bytes
    )
    $folder = Split-Path -Path $Path -Parent
    Ensure-Directory -Path $folder
    [System.IO.File]::WriteAllBytes($Path, $Bytes)
}

function Write-TextFile {
    param(
        [string] $Path,
        [string] $Content
    )
    $folder = Split-Path -Path $Path -Parent
    Ensure-Directory -Path $folder
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
}

function Write-Base64File {
    param(
        [string] $Path,
        [string] $Base64
    )
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
    param(
        [string] $DestinationPath,
        [hashtable] $SourceContent
    )
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

function Initialize-Area {
    param(
        [string] $AreaName,
        [string] $RootPath,
        [System.Collections.IEnumerable] $DocumentPlan,
        [byte[]] $UsrClassBytes,
        [byte[]] $DllBytes
    )

    Write-Host "[$AreaName] 폴더를 준비합니다: $RootPath"
    Ensure-Directory -Path $RootPath
    Clear-Directory -Path $RootPath

    $docsPath = Join-Path $RootPath 'Docs'
    $sysPath = Join-Path $RootPath 'SysCfg'
    Ensure-Directory -Path $docsPath
    Ensure-Directory -Path $sysPath

    foreach ($plan in $DocumentPlan) {
        $filePath = Join-Path $docsPath $plan.FileName
        Write-BytesFile -Path $filePath -Bytes ([byte[]]$plan.Bytes.Clone())
    }

    Write-TextFile -Path (Join-Path $sysPath 'hosts_sample.txt') -Content "127.0.0.1 localhost`n# 테스트용 호스트 파일"
    Write-TextFile -Path (Join-Path $sysPath 'system.env') -Content "APP_ENV=Test`nTRACE=true"
    Write-TextFile -Path (Join-Path $sysPath 'appsettings.json') -Content '{"Logging":{"Level":"Information"},"ConnectionStrings":{"Primary":"Server=127.0.0.1;Database=Test"}}'
    Write-TextFile -Path (Join-Path $sysPath 'config.ini') -Content "[General]`nName=TestSystem`nMode=Simulation"
    Write-TextFile -Path (Join-Path $sysPath 'registry_backup.reg') -Content "Windows Registry Editor Version 5.00`n[HKEY_LOCAL_MACHINE\\SOFTWARE\\SampleCompany]`n\"AreaName\"=\"TestArea\""
    Write-TextFile -Path (Join-Path $sysPath 'sample.csv') -Content "Name,Value`nSample,123"
    Write-TextFile -Path (Join-Path $sysPath 'settings.config') -Content "<?xml version='1.0' encoding='utf-8'?><configuration><appSettings><add key='Mode' value='Test'/></appSettings></configuration>"
    Write-BytesFile -Path (Join-Path $sysPath 'system_like_UsrClass.dat') -Bytes ([byte[]]$UsrClassBytes.Clone())
    Write-BytesFile -Path (Join-Path $sysPath 'sample.dll') -Bytes ([byte[]]$DllBytes.Clone())

    $pngBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/wwAAgMBAJcC/wAAAABJRU5ErkJggg=='
    Write-Base64File -Path (Join-Path $sysPath 'image_1x1.png') -Base64 $pngBase64
    $jpgBase64 = '/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAAkGBxISEhAQEBAQEA8QDxAQEA8PDxAPDxAQFREWFhURFRUYHSggGBolGxUVITEhJSkrLi4uFx8zODMsNygtLisBCgoKDQ0NDg0NDisZFRkrKysrKysrKysrKystKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrK//AABEIAJwBPgMBIgACEQEDEQH/xAAXAAADAQAAAAAAAAAAAAAAAAADBAUG/8QAHBAAAQQDAQAAAAAAAAAAAAAAAQACAxEEEiEx/8QAFwEAAwEAAAAAAAAAAAAAAAAAAQIDBf/EAB4RAAICAQUAAAAAAAAAAAAAAAABAgMEERITIUFR/9oADAMBAAIRAxEAPwDtVLwlh8zvP4STcQduPqbXaW3n1JcTzH//2Q=='

    Write-Base64File -Path (Join-Path $sysPath 'image_1x1.jpg') -Base64 $jpgBase64

    $zipPath = Join-Path $sysPath 'sample.zip'
    New-ZipSample -DestinationPath $zipPath -SourceContent @{ 'readme.txt' = "이 ZIP 파일은 테스트 자동화에서 생성되었습니다." }

}

Write-Host '=== 데이터 보호 테스트용 파일 생성기 시작 ==='
$normalRoot = Read-PathPrompt -PromptText '일반영역 폴더 경로를 입력하세요'
$secureRoot = Read-PathPrompt -PromptText '보안영역 폴더 경로를 입력하세요'
if ($normalRoot -eq $secureRoot) {
    throw '일반영역과 보안영역 경로는 서로 달라야 합니다.'
}

$seed = Get-Random -Maximum 1000000
$rand = [System.Random]::new($seed)

$sizeOptions = @(65536, 262144, 1048576)
$docExtensions = @('doc','docx','ppt','pptx','xls','xlsx','hwp','hwpx','txt')
$documentPlan = New-Object System.Collections.ArrayList
foreach ($ext in $docExtensions) {
    $size = $sizeOptions[$rand.Next(0, $sizeOptions.Count)]
    $fileName = "sample_{0}_{1}.{0}" -f $ext, $size
    $bytes = New-Object byte[] $size
    $rand.NextBytes($bytes)
    [void]$documentPlan.Add([PSCustomObject]@{ FileName = $fileName; Bytes = $bytes })
}

$usrClassBytes = New-Object byte[] 4096
$rand.NextBytes($usrClassBytes)
$dllBytes = New-Object byte[] 32768
$rand.NextBytes($dllBytes)

Initialize-Area -AreaName 'NormalArea' -RootPath $normalRoot -DocumentPlan $documentPlan -UsrClassBytes $usrClassBytes -DllBytes $dllBytes
Initialize-Area -AreaName 'SecureArea' -RootPath $secureRoot -DocumentPlan $documentPlan -UsrClassBytes $usrClassBytes -DllBytes $dllBytes

Write-Host "사용된 난수 시드: $seed"
Write-Host '=== 파일 생성이 완료되었습니다. ==='
