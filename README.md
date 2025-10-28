# Ransomware Validation Automation Script

이 저장소는 보안영역과 일반영역 폴더에 샘플 데이터를 배포하고, RanSim / Atomic Red Team / Caldera 시뮬레이터 준비 상태를 점검한 뒤, 파일 무결성 비교를 통해 랜섬웨어 및 악성코드 침해 여부를 측정하는 PowerShell 스크립트를 제공합니다.

## 주요 기능
- 일반영역 및 보안영역 경로, 보고서 저장 경로를 인터랙티브하게 입력받습니다.
- 각 영역에 9종 문서 확장자(doc, docx, ppt, pptx, xls, xlsx, hwp, hwpx, txt)를 동일하게 배치하되, 확장자별 무작위 용량을 선택해 샘플 데이터를 생성하고 선택 결과(Seed 포함)를 CSV로 기록합니다.
- 시스템 구성/환경 파일과 민감 데이터 예시 파일(.png, .jpg, .zip, .dll, .csv, .reg, .config, .dat 등)도 함께 생성하여 운영 환경을 모사합니다.
- 생성 직후 데이터 보호 성능(문서/시스템 파일 수, 총 용량 등)을 측정해 기준선을 CSV로 남깁니다.
- RanSim, Invoke-AtomicRedTeam 모듈, Caldera 설치 여부를 확인하고 필요 시 다운로드/설치를 돕습니다.
- Atomic Red Team 계획(7개 버킷, 50개 대표 TTP)을 자동 실행하여 악성 행위 대응 성능을 평가하고, 각 시나리오의 성공/실패·영향 경로·Atomic 실행 여부를 CSV·로그로 남깁니다.
- 악성 행위 평가 후 영역별 핵심 지표(무결성 보존률, 쓰기 차단율, 압축/인코딩 무력화율, 유출 차단율 등)와 파일 단위 세부 검증 결과를 별도 CSV로 제공합니다.
- 시뮬레이터 실행 이후 파일 무결성을 재검사하여 변경/누락/신규/정상 파일을 탐지하고 CSV, JSON, 파일 단위 보고서를 생성합니다.

## 사용 방법
1. PowerShell을 **관리자 권한으로 실행**합니다.
2. 스크립트를 복사하여 붙여넣거나 `ransomware_validation.ps1` 파일을 실행합니다.
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\ransomware_validation.ps1
   ```
3. 안내에 따라 일반영역, 보안영역, 보고서 경로를 입력합니다. 폴더가 존재하지 않으면 자동으로 생성합니다.
4. 스크립트가 샘플 데이터를 배포한 뒤 자동으로 데이터 보호 성능을 측정하고 `DataProtection_Baseline_*.csv` 파일을 생성합니다.
5. Atomic Red Team 모듈이 감지되면 스크립트가 자동으로 50개 악성 행위 시나리오를 실행합니다. 결과는 `Malware_Performance_Assessment_*.csv`, `Malware_Assessment_Summary_*.csv`, `Malware_Assessment_FileStatus_*.csv`, `Malware_Assessment_Log_*.txt`로 저장되며, `Malware_Assessment_FileStatus_*.csv`에는 테스트마다 각 파일의 존재 여부·크기·SHA256 해시(전/후)가 기록됩니다.
6. RanSim / Caldera / Invoke-AtomicRedTeam이 설치되어 있지 않으면 스크립트가 자동으로 다운로드와 무인 설치/압축 해제를 시도하고, RanSim 실행 파일이 준비되면 자동으로 기동합니다.
7. 추가 입력 없이 시뮬레이터 준비부터 악성 행위 평가, 최종 랜섬웨어 무결성 검증까지 모두 연속 실행됩니다.
8. 결과는 지정한 보고서 경로에 CSV/JSON으로 저장되며 문서 샘플 계획, 악성 행위 로그, 파일 단위 검증 결과까지 확인할 수 있습니다.

> ⚠️ **주의:** 실제 운영 환경이 아닌, 승인된 테스트 환경에서만 시뮬레이션을 수행하세요. 시뮬레이터 설치 및 실행 시 각 제품의 라이선스 정책과 보안 지침을 준수해야 합니다.

## 보고서 예시
- `DocumentPlan_YYYYMMDD_HHMMSS.csv`: 확장자별 선택된 파일 용량과 난수 시드 기록
- `DataProtection_Baseline_YYYYMMDD_HHMMSS.csv`: 랜섬웨어 실행 전 각 영역의 문서/시스템 파일 현황
- `Malware_Performance_Assessment_YYYYMMDD_HHMMSS.csv`: Atomic Red Team 50개 시나리오 실행 결과(성공/실패, 영향 파일, Atomic 실행 여부)
- `Malware_Assessment_Summary_YYYYMMDD_HHMMSS.csv`: 영역별 핵심 지표(무결성 보존률, 쓰기/압축/유출 차단율 등)
- `Malware_Assessment_FileStatus_YYYYMMDD_HHMMSS.csv`: 악성 행위 시나리오별로 각 파일의 실행 전/후 존재 여부, 크기, SHA256 해시, 변경 여부를 기록한 세부 데이터
- `Malware_Assessment_FinalState_YYYYMMDD_HHMMSS.csv`: 악성 행위 이후 영역별 파일 상태(Intact/Changed/Missing/New)와 해시 비교 결과
- `Malware_Assessment_Log_YYYYMMDD_HHMMSS.txt`: 시나리오별 세부 로그
- `Ransomware_Evaluation_YYYYMMDD_HHMMSS.csv`: 각 영역의 Intact/변경/누락/신규 파일 수 및 침해 여부 요약
- `Ransomware_FileStatus_YYYYMMDD_HHMMSS.csv`: 모든 파일에 대한 상태(Intact/Changed/Missing/New)와 해시 비교 결과
- `Ransomware_Evaluation_Details_YYYYMMDD_HHMMSS.json`: 상세 파일 목록과 해시 정보

## 요구 사항
- Windows PowerShell 5.1 이상 또는 PowerShell 7.x
- 인터넷 연결 (시뮬레이터 다운로드 및 Invoke-AtomicRedTeam 모듈 설치용)
- 관리자 권한

## 라이선스
이 저장소의 스크립트는 보안 평가 및 교육 목적으로 제공되며, 제공된 코드를 이용하는 동안 발생하는 모든 책임은 사용자에게 있습니다.
