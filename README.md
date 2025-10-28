# Ransomware Validation Automation Script

이 저장소는 보안영역과 일반영역 폴더에 이미 준비된 업무 데이터를 활용하거나, 테스트용 데이터를 새로 구성하여 RanSim / Atomic Red Team / Caldera 시뮬레이터 준비 상태를 점검하고, 파일 무결성 비교를 통해 랜섬웨어 및 악성코드 침해 여부를 측정하는 PowerShell 스크립트를 제공합니다.

## 주요 기능
- 일반영역 및 보안영역 경로, 보고서 저장 경로를 인터랙티브하게 입력받습니다.
- 필요 시 `prepare_test_data.ps1` 스크립트를 사용하여 일반영역·보안영역 내부를 초기화하고, 평가에 필요한 문서·시스템 파일(.doc, .ppt, .xls, .hwp, .txt, .png, .jpg, .zip, .dll, .dat 등)을 자동 생성할 수 있습니다. (스크립트는 두 영역 모두에 **동일한** 파일 세트를 다시 배치합니다.)
- 랜섬웨어 검증 스크립트(`ransomware_validation.ps1`)는 각 영역에 이미 배치된 문서/시스템 데이터를 그대로 사용하며, 확장자·용량·해시를 스캔하여 기준 정보를 확보합니다. **필수 확장자나 시스템 샘플이 누락된 경우 자동으로 prepare 스크립트와 동일한 구성을 생성**하므로 추가 경고 없이 테스트를 진행할 수 있습니다.
- 생성 직후 데이터 보호 성능(문서/시스템 파일 수, 총 용량 등)을 측정해 기준선을 CSV로 남깁니다.
- RanSim, Invoke-AtomicRedTeam 모듈, Caldera 설치 여부를 확인하고 필요 시 다운로드/설치를 돕습니다.
- Invoke-AtomicRedTeam 모듈이 있지만 Atomics 콘텐츠가 누락된 경우 모듈 설치 경로나 `C:\AtomicRedTeam`을 자동으로 탐색하고, 필요 시 GitHub에서 Atomics 패키지를 내려받아 배치합니다.
- Atomic Red Team 계획(7개 버킷, 50개 대표 TTP)을 자동 실행하여 악성 행위 대응 성능을 평가하고, 각 시나리오의 성공/실패·영향 경로·Atomic 실행 여부를 CSV·로그로 남깁니다.
- 악성 행위 평가 후 영역별 핵심 지표(무결성 보존률, 쓰기 차단율, 압축/인코딩 무력화율, 유출 차단율 등)와 파일 단위 세부 검증 결과를 별도 CSV로 제공합니다.
- 시뮬레이터 실행 이후 파일 무결성을 재검사하여 변경/누락/신규/정상 파일을 탐지하고 CSV, JSON, 파일 단위 보고서를 생성합니다.

## 사용 방법
1. PowerShell을 **관리자 권한으로 실행**합니다.
2. (선택) 테스트를 위한 전용 데이터를 새로 준비하려면 `prepare_test_data.ps1`을 먼저 실행합니다.
   - 스크립트 실행 시 일반영역/보안영역 경로를 차례대로 입력합니다.
   - 각 영역의 기존 폴더·파일은 모두 삭제되므로, 운영 데이터가 아닌 테스트 전용 경로를 사용해야 합니다.
   - 완료 후 `Docs`, `SysCfg` 폴더 안에 문서 9종과 시스템 모사 파일이 새로 생성되며, 사용된 난수 시드가 콘솔에 표시됩니다.
   - 랜섬웨어 검증 스크립트는 필요한 파일이 없을 때 동일한 구성을 자동으로 재생성하지만, 사전에 데이터를 정리하고 싶다면 이 보조 스크립트를 활용하세요.
3. 랜섬웨어 검증 스크립트를 복사하여 붙여넣거나 `ransomware_validation.ps1` 파일을 실행합니다.
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\ransomware_validation.ps1
   ```
4. 안내에 따라 일반영역, 보안영역, 보고서 경로를 입력합니다. 폴더가 존재하지 않으면 자동으로 생성합니다.
5. 스크립트가 기존 데이터를 스캔한 뒤 자동으로 데이터 보호 성능을 측정하고 `DataProtection_Baseline_*.csv` 파일을 생성합니다.
6. Atomic Red Team 모듈이 감지되면 스크립트가 자동으로 50개 악성 행위 시나리오를 실행합니다. 결과는 `Malware_Performance_Assessment_*.csv`, `Malware_Assessment_Summary_*.csv`, `Malware_Assessment_FileStatus_*.csv`, `Malware_Assessment_Log_*.txt`로 저장되며, `Malware_Assessment_FileStatus_*.csv`에는 테스트마다 각 파일의 존재 여부·크기·SHA256 해시(전/후)가 기록됩니다.
7. RanSim / Caldera / Invoke-AtomicRedTeam이 설치되어 있지 않으면 스크립트가 자동으로 다운로드와 무인 설치/압축 해제를 시도하고, 손상된 압축 파일이 감지되면 삭제 후 한 번 더 재다운로드합니다. RanSim 실행 파일이 준비되면 자동으로 기동하며, 자동 다운로드가 끝내 실패하면 설치 파일이 있는 폴더 또는 파일 경로를 입력해 수동 패키지를 사용할 수 있습니다.
8. 추가 입력 없이 시뮬레이터 준비부터 악성 행위 평가, 최종 랜섬웨어 무결성 검증까지 모두 연속 실행됩니다.
9. 결과는 지정한 보고서 경로에 CSV/JSON으로 저장되며 악성 행위 로그와 파일 단위 검증 결과까지 확인할 수 있습니다.

> ⚠️ **주의:** 실제 운영 환경이 아닌, 승인된 테스트 환경에서만 시뮬레이션을 수행하세요. 시뮬레이터 설치 및 실행 시 각 제품의 라이선스 정책과 보안 지침을 준수해야 합니다.

## 네트워크/인증서 문제 해결
- 스크립트는 RanSim, Atomic Red Team, Caldera 패키지를 내려받기 전에 TLS 1.0/1.1/1.2를 모두 활성화합니다.
- 사내 프록시나 SSL 가로채기 장비가 존재해 인증서 신뢰 오류가 발생할 경우, 해당 장비의 루트 인증서를 **로컬 컴퓨터 > 신뢰할 수 있는 루트 인증 기관** 저장소에 추가해야 합니다.
- 인터넷 차단 환경이라면, 공인 네트워크에서 공식 패키지를 미리 내려받아 `C:\Temp\SecurityTools` 또는 사용자가 지정한 스테이징 폴더에 복사한 뒤 스크립트를 다시 실행하세요. 이미 내려받은 패키지가 손상돼 압축이 실패하면 스크립트가 자동으로 삭제하고 재시도하며, 반복 실패 시 수동 경로 입력으로 진행할 수 있습니다.

## 보고서 예시
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
