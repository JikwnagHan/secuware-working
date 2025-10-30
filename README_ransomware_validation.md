# 랜섬웨어 침해 여부 검증 자동화 (`ransomware_validation.ps1`)

`ransomware_validation.ps1`는 일반영역과 보안영역의 현재 파일 자산을 기준으로 악성코드/랜섬웨어 행위를 재현하고 침해 여부를 분석하는 통합 스크립트입니다. 관리자 권한 PowerShell에 붙여넣어 실행하면 경로 입력부터 보고서 생성까지 자동으로 진행됩니다.

## 준비 사항
- Windows PowerShell 5.1 이상 또는 PowerShell 7.x
- 관리자 권한 PowerShell 세션
- 인터넷 연결(Invoke-AtomicRedTeam 모듈, RanSim, Caldera 자동 다운로드에 필요)
- 테스트 전용 경로(스크립트가 Docs/SysCfg 하위 폴더를 재구성하고 `_AssessmentWorkspace`를 생성합니다)

## 실행 절차
1. 스크립트를 실행하고 안내에 따라 **일반영역**, **보안영역**, **결과 저장 폴더** 경로를 차례대로 입력합니다.
2. 각 영역의 `Docs`/`SysCfg` 폴더를 점검하여 필수 문서 9종과 시스템·환경 샘플이 없으면 자동으로 다시 채웁니다. (모두 동일한 난수 시드로 생성되어 두 영역이 같은 데이터 집합을 사용합니다.)
3. 영역별 문서·시스템 파일 수와 용량을 기준선 CSV로 저장한 뒤, 파일별 SHA-256 스냅샷을 확보합니다.
4. **Atomic Red Team** 모듈과 atomics 콘텐츠를 찾고, 필요 시 GitHub에서 내려받거나 수동 경로를 요청합니다.
5. 7개 버킷 30개 대표 악성 행위를 실행하여 파일 변조·신규 생성·권한 변경 여부를 기록하고, Atomic 실행 로그/CSV를 생성합니다.
6. RanSim, Caldera 설치 여부를 확인하여 자동 다운로드·설치, 또는 수동 경로 입력을 안내합니다.
7. RanSim 기반 랜섬웨어 시뮬레이션 전후 상태를 비교해 변경/신규/누락 파일 수를 산출하고, CSV/JSON 세부 보고서를 생성합니다.
8. 콘솔에 출력된 경로에서 모든 결과 파일(CSV·JSON·로그 등)을 확인합니다.

## 생성되는 산출물
- `DataProtection_Baseline_*.csv` : 영역별 문서/시스템 파일 개수, 총 용량, 최종 수정 시각 등 기준선 정보
- `Malware_Performance_Assessment_*.csv` : 버킷/기술별 악성 행위 실행 결과, Atomic 실행 여부 및 영향 파일 목록
- `Malware_Assessment_Summary_*.csv` : 영역별 Intact/Changed/New/Missing 파일 수와 차단율(쓰기/압축/유출) 요약
- `Malware_Assessment_FileStatus_*.csv` : 악성 행위별 영향을 받은 파일의 존재 여부, 크기, 해시 변동 기록
- `Malware_Assessment_FinalState_*.csv` : 기준선과 비교한 최종 파일 상태(Intact/Changed/New/Missing)
- `Malware_Assessment_Log_*.txt` : Atomic 모듈 감지, 각 행위 실행 로그, 생성된 보고서 경로 기록
- `Ransomware_Evaluation_*.csv` : RanSim 실행 전후 영역별 Intact/Changed/New/Missing 건수 및 침해 여부
- `Ransomware_Evaluation_Details_*.json` : 파일 단위 세부 상태를 포함한 JSON 결과
- `Ransomware_FileStatus_*.csv` : 파일별 상대 경로, 기준선/현재 해시, 상태, 비고
- `SimulatorPackages_*` 폴더 : RanSim/Caldera 자동 다운로드 시 임시 저장되는 패키지 및 압축 해제 내용

## 시뮬레이터 준비 및 문제 해결
- **Invoke-AtomicRedTeam**: 모듈은 설치되어 있으나 atomics 폴더가 없으면 GitHub 저장소를 자동 다운로드하거나, `ATOMIC_RED_TEAM_PATH` 환경 변수/`C:\AtomicRedTeam\atomics`에 수동 배치하도록 안내합니다.
- **RanSim**: 기본 경로 `C:\KB4\Newsim\Ranstart.exe`를 확인하고, 자동 다운로드 실패 시 설치 파일(.msi/.exe) 경로를 입력받아 수동 설치를 수행합니다.
- **Caldera**: 최신 릴리스를 다운로드 후 지정 폴더에 압축 해제합니다. 자동 다운로드 실패 시 수동 패키지 배치 경로를 안내합니다.
- 네트워크 차단이나 TLS 오류로 다운로드가 실패하면 스크립트가 신뢰할 수 있는 네트워크에서의 수동 확보 및 임시 폴더 배치를 권장합니다.

## 권장 운영 팁
- 테스트는 반드시 운영 데이터와 분리된 전용 폴더에서 수행하세요.
- 보안 솔루션(EDR/백신)의 정책에 따라 시뮬레이터 실행이 차단될 수 있으므로, 필요한 예외 정책을 사전에 검토하세요.
- 실행 후 결과 CSV/JSON/로그를 보관하여 침해 징후 추적 및 대응 정책 수립에 활용하세요.
