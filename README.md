# Ransomware Validation Automation Script

이 저장소는 보안영역과 일반영역 폴더에 샘플 데이터를 배포하고, RanSim / Atomic Red Team / Caldera 시뮬레이터 준비 상태를 점검한 뒤, 파일 무결성 비교를 통해 랜섬웨어 침해 여부를 측정하는 PowerShell 스크립트를 제공합니다.

## 주요 기능
- 일반영역 및 보안영역 경로, 보고서 저장 경로를 인터랙티브하게 입력받습니다.
- 각 영역에 다양한 문서 형식(doc, docx, ppt, pptx, xls, xlsx, hwp, hwpx, txt, pdf)을 포함한 샘플 데이터를 생성합니다.
- 시스템 구성/환경 파일과 민감 데이터 예시 파일도 함께 생성하여 운영 환경을 모사합니다.
- RanSim, Invoke-AtomicRedTeam 모듈, Caldera 설치 여부를 확인하고 필요 시 다운로드/설치를 돕습니다.
- 시뮬레이터 실행 이후 파일 무결성을 재검사하여 변경/누락/신규 파일을 탐지하고 CSV 및 JSON 보고서를 생성합니다.

## 사용 방법
1. PowerShell을 **관리자 권한으로 실행**합니다.
2. 스크립트를 복사하여 붙여넣거나 `ransomware_validation.ps1` 파일을 실행합니다.
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\ransomware_validation.ps1
   ```
3. 안내에 따라 일반영역, 보안영역, 보고서 경로를 입력합니다. 폴더가 존재하지 않으면 자동으로 생성합니다.
4. RanSim / Atomic Red Team / Caldera 설치 여부 확인 단계에서 자동 다운로드를 원하면 `y`를 입력합니다. 수동 설치도 가능합니다.
5. 각 시뮬레이터의 랜섬웨어 테스트를 완료한 뒤 Enter 키를 눌러 파일 무결성 평가를 진행합니다.
6. 결과는 지정한 보고서 경로에 CSV 및 JSON 파일로 저장됩니다.

> ⚠️ **주의:** 실제 운영 환경이 아닌, 승인된 테스트 환경에서만 시뮬레이션을 수행하세요. 시뮬레이터 설치 및 실행 시 각 제품의 라이선스 정책과 보안 지침을 준수해야 합니다.

## 보고서 예시
- `Ransomware_Evaluation_YYYYMMDD_HHMMSS.csv`: 각 영역의 변경/누락/신규 파일 수 및 침해 여부 요약
- `Ransomware_Evaluation_Details_YYYYMMDD_HHMMSS.json`: 상세 파일 목록과 해시 정보

## 요구 사항
- Windows PowerShell 5.1 이상 또는 PowerShell 7.x
- 인터넷 연결 (시뮬레이터 다운로드 및 Invoke-AtomicRedTeam 모듈 설치용)
- 관리자 권한

## 라이선스
이 저장소의 스크립트는 보안 평가 및 교육 목적으로 제공되며, 제공된 코드를 이용하는 동안 발생하는 모든 책임은 사용자에게 있습니다.
