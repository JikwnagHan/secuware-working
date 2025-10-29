# 데이터 보호 성능평가 자동화

`data_protection_assessment.ps1`은 일반영역과 보안영역에 테스트 데이터를 자동으로 구성하고, 악성코드/랜섬웨어 시나리오를 연속 실행하여 데이터 보호 성능을 정량적으로 평가하는 PowerShell 자동화 스크립트입니다. 관리자 권한 PowerShell 콘솔에 붙여넣으면 즉시 실행할 수 있도록 설계되었습니다.

## 주요 기능
1. **경로 입력**: 일반영역, 보안영역, 결과 저장 경로(.xlsxm 파일 경로 또는 폴더)를 순차적으로 입력받습니다.
2. **데이터 재구성**: 기존 문서/시스템 파일이 존재하더라도 모두 삭제한 뒤, 두 영역에 동일한 문서 9종×랜덤 크기 및 시스템/환경 파일 세트를 재생성합니다.
3. **시뮬레이터 점검/설치**: RanSim, Invoke-AtomicRedTeam 모듈·Atomics 콘텐츠, Caldera 존재 여부를 확인하고, 누락 시 자동 다운로드를 시도합니다.
4. **악성코드 침해 테스트**: Atomic 7개 버킷, 30개 대표 시나리오를 스크립트 내장 동작으로 재현해 파일 변경·생성·속성 조작을 수행하고 파일 단위 결과를 수집합니다.
5. **랜섬웨어 침해 테스트**: RanSim 실행 파일을 자동 호출(없을 경우 수동 경로 입력)한 후, 침해 여부를 파일 무결성 기준으로 비교합니다.
6. **보고서 출력**: CSV/JSON뿐 아니라 XLSXM, DOCX 보고서를 자동 생성하여 평가 결과를 요약합니다.

## 요구 사항
- Windows PowerShell 5.1 이상 또는 PowerShell 7.x
- 관리자 권한 콘솔 실행
- 인터넷 연결(시뮬레이터 다운로드/모듈 설치 시 필요)
- 테스트 전용 경로 사용 (스크립트가 지정 경로의 기존 파일을 모두 삭제함)

## 사용 방법
1. **PowerShell 관리자 콘솔 실행** 후 아래 명령으로 스크립트를 실행합니다.
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\data_protection_assessment.ps1
   ```
2. 안내에 따라 일반영역, 보안영역, 결과 저장 경로를 입력합니다.
   - 결과 경로에 `.xlsxm` 파일을 직접 지정하면 해당 파일 이름으로 보고서가 생성됩니다.
   - 폴더를 입력하면 `DataProtection_Report_yyyyMMdd_HHmmss.xlsxm/.docx` 파일이 생성됩니다.
3. 스크립트가 두 영역을 초기화하고, RanSim·Atomic·Caldera 설치 상태를 자동 확인합니다.
4. 악성행위 30개 시나리오와 RanSim 실행이 순차적으로 진행되며, 추가 입력 없이 결과 파일이 생성됩니다.
5. 실행 완료 메시지에 표시된 경로에서 CSV/JSON/XLSXM/DOCX 파일을 확인합니다.

## 생성되는 파일
- `csv/Baseline_*.csv` : 재생성 직후 파일 크기·SHA256 기준선
- `csv/Malware_Assessment_*.csv` : 악성행위 시나리오별 파일 상태(Exists/Size/SHA256 전·후)
- `csv/Ransomware_Assessment_*.csv` : RanSim 실행 전/후 파일 상태 비교
- `csv/Summary_*.csv` : Stage(악성코드/랜섬웨어)별 Intact/Changed/New/Missing 요약
- `json/Malware_Assessment_*.json`, `json/Ransomware_Assessment_*.json`
- `DataProtection_Report_*.xlsxm` : Summary/Malware/Ransomware 시트 포함 엑셀 보고서
- `DataProtection_Report_*.docx` : 실행 요약, 시뮬레이터 경로, 결과 파일 위치 안내

## 문제 해결 팁
- **Invoke-AtomicRedTeam 모듈 미설치**: 스크립트가 자동 설치를 시도하며, 실패 시 PowerShell Gallery 접근 권한을 확인하세요.
- **Atomics 폴더 누락**: GitHub 다운로드가 차단된 경우, <https://github.com/redcanaryco/atomic-red-team> 저장소를 수동으로 내려받아 `C:\AtomicRedTeam\atomics` 또는 `ATOMIC_RED_TEAM_PATH`에 배치하세요.
- **RanSim 다운로드 오류**: TLS 검증 실패 시 사내 프록시/SSL 검사를 확인하고 신뢰할 수 있는 네트워크에서 `RanSim-Setup.msi`를 내려받아 `C:\Temp\RanSim`에 복사한 뒤 스크립트를 재실행하세요.
- **Caldera 미설치**: 자동 압축 해제가 실패하면, 공식 GitHub 릴리스를 수동으로 내려받아 `C:\Caldera`에 풀어 둡니다.

## 보안 및 운영 주의사항
- 실제 운영 데이터가 아닌 **전용 테스트 경로**를 사용하십시오.
- RanSim/Atomic/Caldera 실행은 보안 솔루션 정책에 영향을 줄 수 있으므로 사전 승인된 환경에서만 진행하세요.
- 보고서에 포함된 데이터(해시/경로)는 외부 반출 전에 조직 정책을 확인하세요.

## 추가 스크립트
- `prepare_test_data.ps1`: 필요 시 별도로 일반/보안 영역을 초기화하고 동일한 샘플 세트를 구성하는 보조 스크립트입니다. 통합 스크립트 실행 전에 수동으로 환경을 정리하고 싶을 때 사용합니다.

문의 사항이나 개선 제안은 이 저장소의 이슈 트래커를 통해 전달해 주세요.
