# data_protection_assessment.ps1 사용 가이드

`data_protection_assessment.ps1`은 일반영역(Normal Area)과 보안영역(Secure Area)을 초기화하고, 동일한 테스트 데이터를 배치한 뒤 악성코드(Atomic Red Team) 및 랜섬웨어(RanSim) 시뮬레이션을 수행해 데이터 보호 능력을 자동으로 평가하는 PowerShell 스크립트입니다. 모든 단계는 관리자 권한 PowerShell 콘솔에서 순차적으로 진행되며, 결과는 CSV/JSON/XLSX/DOCX 보고서로 정리됩니다.

## 핵심 기능
1. **경로 입력 자동화** – 일반영역, 보안영역, 결과 저장 위치(.xlsx 파일 경로 또는 폴더)를 차례대로 입력받고 누락 시 재요청합니다.
2. **데이터 세트 재구성** – 두 영역의 기존 파일을 삭제한 뒤, 문서 9종(랜덤 크기)과 시스템/환경 파일 5종을 동일한 내용으로 다시 생성합니다.
3. **시뮬레이터 점검/설치** – RanSim, Invoke-AtomicRedTeam(모듈 및 Atomics), Caldera의 설치 상태를 확인하고 필요 시 자동 다운로드를 시도합니다. 네트워크 차단 시 수동 경로 입력을 안내합니다.
4. **악성코드 평가(50→30 대표 시나리오)** – Atomic Red Team의 7개 버킷, 30개 대표 기법을 실행하거나 내부 모의 동작으로 재현하여 파일 변경/생성 여부를 추적합니다.
5. **랜섬웨어 평가** – RanSim 실행 파일을 호출하여 암호화 시뮬레이션을 수행하고, 영역별 변경·신규·누락 파일 수를 집계합니다.
6. **보고서 생성** – Baseline, Malware, Ransomware CSV/JSON과 요약 CSV, Excel(XLSX) 요약 보고서, Word(DOCX) 분석 보고서를 자동 생성합니다.

## 요구 사항
- Windows PowerShell 5.1 이상 또는 PowerShell 7.x
- 관리자 권한 콘솔 실행
- 인터넷 연결(시뮬레이터 자동 설치 시 필요)
- 테스트 전용 경로 사용(스크립트가 지정 경로의 파일을 삭제/재생성)

## 빠른 시작
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\data_protection_assessment.ps1
```
1. 실행 후 안내에 따라 일반영역, 보안영역, 결과 저장 경로를 입력합니다.
2. 결과 경로에 `.xlsx` 파일명을 지정하면 해당 이름으로 보고서가 생성되며, 폴더를 입력하면 스크립트가 `DataProtection_Report_yyyyMMdd_HHmmss.xlsx/.docx`를 작성합니다.
3. 스크립트가 영역 초기화 → 샘플 데이터 생성 → 시뮬레이터 확인/설치 → 악성코드 평가 → 랜섬웨어 평가 순으로 진행합니다.
4. 종료 메시지에 출력되는 경로에서 CSV/JSON/XLSX/DOCX 파일을 확인합니다.

## 평가 워크플로
1. **영역 초기화 및 샘플 생성**
   - 두 영역의 기존 데이터를 삭제하고 문서(.doc, .docx, .ppt, .pptx, .xls, .xlsx, .hwp, .hwpx, .txt)와 시스템성 파일(hosts, system.env 등) 총 14개를 동일한 내용으로 생성합니다.
   - 생성된 파일의 크기와 SHA256 해시를 Baseline CSV에 기록합니다.
2. **기준 무결성 측정**
   - 초기 상태에서 파일 존재 여부, 크기, 해시를 수집해 `DataProtection_Baseline_*.csv`로 저장합니다.
3. **악성코드 성능 평가**
   - Atomic Red Team 기법을 7개 버킷(파일 조작, 압축/인코딩, 스크립팅, 권한/속성, 정리, 열거, 유출 유사)으로 묶어 30개 대표 시나리오를 실행합니다.
   - 각 시나리오 전후의 Exists/Size/Hash를 비교하여 `Malware_Assessment_*.csv`와 `Malware_Assessment_FileStatus_*.csv`에 기록하고, 요약 결과를 `Malware_Assessment_Summary_*.csv`로 저장합니다.
4. **랜섬웨어 성능 평가**
   - RanSim을 실행하여 영역별 변경/신규/누락 파일 수를 집계하고, 파일 단위 결과(`Ransomware_FileStatus_*.csv`)와 세부 JSON을 생성합니다.
5. **보고서 작성**
   - **XLSX 보고서**: Baseline/Malware/Ransomware 요약 시트와 Stage·Area별 Intact/Changed/New/Missing 통계를 포함합니다.
   - **DOCX 분석 보고서**: 실행 환경, 시뮬레이터 상태, 단계별 핵심 지표, 해석 및 권장 조치를 자연어로 정리합니다.

## 생성 파일 안내
- `csv/DataProtection_Baseline_*.csv`
- `csv/Malware_Assessment_*.csv`, `csv/Malware_Assessment_FileStatus_*.csv`, `csv/Malware_Assessment_Summary_*.csv`
- `csv/Ransomware_Assessment_*.csv`, `csv/Ransomware_FileStatus_*.csv`
- `json/Malware_Assessment_Details_*.json`, `json/Ransomware_Evaluation_Details_*.json`
- `DataProtection_Report_*.xlsx`
- `DataProtection_Analysis_*.docx`

## 자주 발생하는 이슈와 대응
| 증상 | 원인 | 해결 방법 |
| --- | --- | --- |
| RanSim 자동 설치 실패 | TLS 차단 또는 인증서 검사 | 사내 프록시 예외를 구성하거나 공식 사이트에서 패키지를 수동 다운로드 후 경로 입력 |
| Atomics 폴더 미확보 | GitHub 다운로드 차단 | <https://github.com/redcanaryco/atomic-red-team> 저장소를 수동으로 내려받아 `C:\AtomicRedTeam\atomics` 또는 `ATOMIC_RED_TEAM_PATH` 환경변수 지정 |
| Invoke-AtomicRedTeam 모듈 누락 | PowerShell Gallery 접근 실패 | 관리자 PowerShell에서 `Install-Module Invoke-AtomicRedTeam -Force` 실행 후 재시도 |
| PowerShell 미설치 환경 | Linux 컨테이너 등 | Windows PowerShell 5.1 또는 PowerShell 7을 설치한 뒤 실행 |

## 안전 수칙
- 실제 운영 데이터를 스크립트 대상으로 사용하지 마십시오.
- RanSim/Atomic/Caldera 실행은 보안 솔루션 정책에 영향을 줄 수 있으므로 테스트 전용 장비에서 수행하세요.
- 생성된 보고서에는 경로·해시 값이 포함되므로 외부 반출 시 보안 정책을 준수하십시오.

추가 문의나 개선 제안은 이 저장소의 이슈 트래커를 통해 전달해 주세요.
