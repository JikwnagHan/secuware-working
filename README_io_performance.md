# 입출력 속도 성능평가 자동화 (`io_performance_assessment.ps1`)

`io_performance_assessment.ps1`은 초기화된 저장장치의 일반영역과 보안영역에 대해 동일한 샘플 데이터를 15회 반복 저장/읽기하여 속도를 측정하고, 보안영역이 일반영역 대비 90% 이상의 성능을 유지하는지 판정하는 자동화 스크립트입니다.

## 준비 사항
- Windows PowerShell 5.1 이상 또는 PowerShell 7.x
- 관리자 권한 콘솔 실행 권장
- 충분한 저장 공간과 테스트 전용 경로 (측정 과정에서 다수의 대용량 파일이 생성되고 삭제됩니다)

## 실행 방법
1. 관리자 PowerShell에서 아래 명령으로 스크립트를 실행합니다.
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\io_performance_assessment.ps1
   ```
2. 안내에 따라 다음 경로를 순서대로 입력합니다.
   - 일반영역 위치 (예: `D:\Test\NormalArea`)
   - 보안영역 위치 (예: `D:\Test\SecureArea`)
   - 샘플 데이터 위치 (예: `D:\Test\Dataset`) – 10종 샘플 파일이 없으면 자동 생성하며, 기존 파일이 있으면 그대로 활용합니다.
   - 결과 데이터 저장 위치 (폴더 또는 `.xlsx` 경로)
3. 스크립트가 일반/보안 영역을 초기화하고, 일반 영역에서 샘플 데이터를 저장/읽기 각각 15회 연속 측정한 뒤 즉시 보안 영역에 대해 동일한 절차를 반복합니다.
4. 실행이 완료되면 콘솔에 표시된 경로에서 CSV(세부/요약/비율), XLSX, DOCX 보고서를 확인합니다.

### 판정 기준
- 저장·읽기 지연 시간은 각 파일을 저장/읽기할 때의 시작·종료 시각 차이(T_A, T_S)로 계산됩니다.
- 보안영역 성능 비율은 `(T_A / T_S) × 100`으로 산출하며, 읽기·쓰기 각각 90% 이상이면 합격으로 판정됩니다.
- 보고서에는 평균 지연(ms), 평균 MB/s, 각 작업의 성능 비율과 합격 여부가 모두 기록됩니다.

## 생성되는 산출물
- `csv/IO_Performance_*.csv` : 반복 측정 결과 (RunId, Iter, Path, Scenario, Operation, SizeMB, 저장/읽기 시작·종료 시각, 지연(ms), MBps 등)
- `csv/IO_Performance_Summary_*.csv` : 시나리오/작업별 평균 시간 및 MB/s
- `csv/IO_Performance_Ratios_*.csv` : 보안영역 성능이 일반영역 대비 몇 %인지와 90% 기준 충족 여부
- `IO_Performance_Report_*.xlsx` : Summary/Details 시트 포함 엑셀 보고서
- `IO_Performance_Analysis_Report_*.docx` : 평균 성능, 90% 판정 결과, 권장 후속 조치를 정리한 분석 보고서

## 참고 사항
- 실측 결과는 테스트 환경(디스크 유형, 백신, 백그라운드 작업 등)에 따라 달라집니다. 일관된 비교를 위해 가능하면 동일 조건에서 반복 측정하십시오.
- 보안영역 정책(암호화, 접근 제어)이 변경된 경우 스크립트를 다시 실행해 성능 변화를 비교할 수 있습니다.

문제가 발생하면 CSV/로그 데이터를 참고하여 병목 구간을 확인한 뒤, 스토리지 구성 및 정책을 점검하세요.
