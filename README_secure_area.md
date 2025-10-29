# Secure Area Performance Assessment Script

이 문서는 `secure_area_performance.ps1` 스크립트를 사용하여 보안영역(대상 폴더)에 대한
쓰기/읽기/무결성 검증을 수행하는 방법을 설명합니다.

## 요구 사항
- Windows PowerShell 5.1 이상 (관리자 권장)
- 테스트를 위한 보안영역 경로와 샘플 데이터 저장 경로
- 결과 파일을 저장할 로컬/네트워크 폴더 또는 `.xlsx` 파일 경로

## 실행 절차
1. PowerShell을 관리자 권한으로 실행합니다.
2. 스크립트를 저장한 폴더로 이동합니다.
3. 다음 명령을 입력하여 스크립트를 실행합니다.
   ```powershell
   .\secure_area_performance.ps1
   ```
4. 안내에 따라 아래 정보를 순서대로 입력합니다.
   - 저장장치 종류 (예: `1`, `SSD`, `USB` 등)
   - 대상 보안영역 경로 (예: `E:\SecureArea`)
   - 샘플 데이터를 생성/보관할 경로
   - 결과 데이터를 저장할 경로 (폴더 또는 `.xlsx` 파일 경로)

## 동작 개요
- 스크립트는 난수 시드를 이용해 문서 9종과 시스템/환경 데이터를 샘플로 생성합니다.
- 샘플 데이터는 `Docs`, `SysCfg` 구조로 구성되며, PNG/JPG/ZIP 등 다양한 파일 형식이 포함됩니다.
- 보안영역 폴더의 기존 내용을 정리한 뒤 샘플 데이터를 복사하고, 쓰기·읽기·SHA256 해시 비교를 수행합니다.
- 세부 결과(파일별 상태)와 요약 결과(카테고리별 PASS/FAIL 집계)를 CSV/JSON/XLSX로 저장하고,
  동일한 내용을 포함한 DOCX 분석 보고서를 생성합니다.

## 생성되는 산출물
- `csv/SecureArea_TestDetails_yyyymmdd_HHmmss.csv`
- `csv/SecureArea_TestSummary_yyyymmdd_HHmmss.csv`
- `json/SecureArea_TestDetails_yyyymmdd_HHmmss.json`
- `SecureArea_TestReport_yyyymmdd_HHmmss.xlsx` (또는 사용자가 지정한 `.xlsx` 경로)
- `Analysis_Report_yyyymmdd_HHmmss.docx`

## 보고서 구성
DOCX 분석 보고서에는 다음 정보가 포함됩니다.
- 실행 일시, 난수 시드, 저장장치 유형 및 WMI로 추출한 장치 속성
- 문서 데이터/시스템 데이터/전체 PASS·FAIL 건수와 성공률
- 실패 항목 분석 시사점과 권장 후속 조치

## 문제 해결 가이드
- **Atomics 등 외부 도구가 필요 없음**: 본 스크립트는 샘플 생성과 I/O 검증만 수행합니다.
- **권한 오류 발생 시**: 보안 소프트웨어나 접근 제어 정책이 쓰기/삭제를 차단할 수 있으므로 관리자 권한으로 실행하고 예외 정책을 확인하세요.
- **보고서가 생성되지 않을 때**: 결과 경로에 대한 쓰기 권한을 확인하고, `.xlsx` 파일을 지정한 경우 다른 프로그램에서 열려 있지 않은지 확인하세요.

필요에 따라 생성된 CSV/XLSX를 추가 분석에 활용하거나, DOCX 보고서를 그대로 성능 평가 결과 문서로 제출할 수 있습니다.
