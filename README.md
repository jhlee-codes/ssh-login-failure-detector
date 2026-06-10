# Security Log Analyzer

Linux SSH 인증 로그와 AWS CloudTrail 로그를 분석하여 보안 이상 징후를 탐지하는 로그 분석 프로젝트입니다.

SSH Brute Force 의심 행위, 반복 실패 후 성공 로그인, AWS 콘솔 로그인 위험 이벤트, 민감한 IAM 변경, SSH 포트 전체 공개, 반복 AccessDenied 이벤트를 탐지하고 TXT 및 Markdown 리포트로 저장합니다.

## 프로젝트 목적

이 프로젝트는 보안 로그 분석, 탐지 기준 설계, 사고 판단, 대응 방안 정리 과정을 연습하기 위해 진행했습니다.

주요 목적은 다음과 같습니다.

* Linux SSH 인증 로그 구조 이해
* SSH Brute Force 의심 행위 탐지
* 실패 후 성공 로그인 이벤트 분석
* AWS CloudTrail 기반 보안 이벤트 탐지
* Bash와 Python을 활용한 보안 분석 자동화
* 분석 결과를 리포트 형태로 정리하는 연습

## 프로젝트 구조

```text
security-log-analyzer/
├── README.md
├── linux/
│   └── ssh_detector.sh
├── python/
│   └── ssh_detector.py
├── aws/
│   ├── cloudtrail_analyzer.py
│   └── sample_cloudtrail_logs/
│       └── cloudtrail_sample.json
├── sample_logs/
│   ├── secure_sample.log
│   ├── normal_login.log
│   ├── brute_force_attack.log
│   ├── failed_then_success.log
│   └── mixed_case.log
└── result/
    ├── ssh_detection_result_*.txt
    ├── ssh_detection_report_*.md
    ├── ssh_detection_result_python_*.txt
    ├── ssh_detection_report_python_*.md
    ├── aws_cloudtrail_result_*.txt
    └── aws_cloudtrail_report_*.md
```

`result/` 디렉터리는 분석 스크립트 실행 시 자동 생성됩니다.

## 주요 기능

### 1. SSH 로그인 실패 탐지

Linux 인증 로그에서 `Failed password` 이벤트를 추출하고 IP별 실패 횟수를 집계합니다.

### 2. 시간 범위 기반 SSH 탐지

동일 IP에서 1시간 내 로그인 실패가 임계치 이상 발생하면 단시간 집중 공격 가능성이 있는 이벤트로 분류합니다.

### 3. 실패 후 성공 로그인 탐지

동일 IP에서 반복적인 로그인 실패가 발생한 뒤 `Accepted password` 또는 `Accepted publickey` 로그인이 성공한 경우 침해 가능성이 있는 이벤트로 탐지합니다.

### 4. AWS CloudTrail 보안 이벤트 탐지

CloudTrail JSON 로그에서 다음 이벤트를 탐지합니다.

* AWS 콘솔 로그인 실패
* Root 계정 콘솔 로그인 성공
* MFA 미사용 콘솔 로그인
* Access Key 생성, 정책 연결 등 민감한 IAM 변경
* 보안 그룹 SSH 22번 포트 전체 공개
* 동일 IP의 반복 AccessDenied 또는 UnauthorizedOperation

### 5. TXT 및 Markdown 리포트 생성

분석 결과는 `result/` 디렉터리에 TXT 파일과 Markdown 리포트로 저장됩니다.

## 탐지 기준

### SSH 로그

| 항목 | 기준 |
|---|---|
| 탐지 대상 | Linux SSH 인증 로그 |
| 실패 로그인 키워드 | `Failed password` |
| 성공 로그인 키워드 | `Accepted password`, `Accepted publickey` |
| 기본 임계치 | 동일 IP에서 로그인 실패 5회 이상 |
| 시간 범위 기준 | 동일 IP에서 1시간 내 로그인 실패 5회 이상 |
| 위험도 기준 | 10회 이상 실패 시 HIGH, 그 외 MEDIUM |

### AWS CloudTrail 로그

| 탐지 항목 | 위험도 | 기준 |
|---|---|---|
| ConsoleLogin Failure | MEDIUM | AWS 콘솔 로그인 실패 |
| Root ConsoleLogin Success | HIGH | Root 계정 콘솔 로그인 성공 |
| ConsoleLogin Without MFA | MEDIUM/HIGH | MFA 없이 콘솔 로그인 성공 |
| Sensitive IAM Change | HIGH | Access Key 생성, IAM 정책 연결/수정 등 |
| SSH Open to World | HIGH | 보안 그룹에서 SSH 22번 포트가 `0.0.0.0/0` 또는 `::/0`에 공개 |
| Repeated AccessDenied | MEDIUM | 동일 IP에서 AccessDenied 계열 이벤트 3회 이상 |

## 실행 방법

### 1. Bash 기반 SSH 로그 분석

```bash
chmod +x linux/ssh_detector.sh
./linux/ssh_detector.sh
```

기본적으로 `sample_logs/secure_sample.log` 파일을 분석하며, 기본 임계치는 5회입니다.

로그 파일과 임계치를 직접 지정할 수 있습니다.

```bash
./linux/ssh_detector.sh sample_logs/brute_force_attack.log 5
```

실제 Linux 로그를 분석할 수도 있습니다.

```bash
sudo ./linux/ssh_detector.sh /var/log/secure 5
sudo ./linux/ssh_detector.sh /var/log/auth.log 5
```

실행 결과 파일 예시는 다음과 같습니다.

```text
result/ssh_detection_result_YYYYMMDD_HHMMSS.txt
result/ssh_detection_report_YYYYMMDD_HHMMSS.md
```

### 2. Python 기반 SSH 로그 분석

```bash
python3 python/ssh_detector.py
```

로그 파일과 임계치를 지정할 수 있습니다.

```bash
python3 python/ssh_detector.py sample_logs/failed_then_success.log 5
```

실행 결과 파일 예시는 다음과 같습니다.

```text
result/ssh_detection_result_python_YYYYMMDD_HHMMSS.txt
result/ssh_detection_report_python_YYYYMMDD_HHMMSS.md
```

### 3. AWS CloudTrail 로그 분석

```bash
python3 aws/cloudtrail_analyzer.py
```

기본적으로 `aws/sample_cloudtrail_logs/cloudtrail_sample.json` 파일을 분석하며, 반복 AccessDenied 기본 임계치는 3회입니다.

CloudTrail 로그 파일과 임계치를 직접 지정할 수 있습니다.

```bash
python3 aws/cloudtrail_analyzer.py aws/sample_cloudtrail_logs/cloudtrail_sample.json 3
```

실행 결과 파일 예시는 다음과 같습니다.

```text
result/aws_cloudtrail_result_YYYYMMDD_HHMMSS.txt
result/aws_cloudtrail_report_YYYYMMDD_HHMMSS.md
```

## 실행 결과 예시

### SSH 탐지 결과

```text
[MEDIUM] 의심 IP 탐지
IP 주소       : 192.168.56.101
실패 횟수     : 5
탐지 사유     : 전체 로그 기준 동일 IP에서 로그인 실패 5회 이상 발생
권장 대응     : 반복 로그인 실패 여부 모니터링, 접속 출처 확인
```

### 실패 후 성공 로그인 탐지 결과

```text
[HIGH] 실패 후 성공 로그인 탐지
IP 주소       : 192.168.56.101
성공 계정     : user1
인증 방식     : password
이전 실패 횟수 : 5
탐지 사유     : 동일 IP에서 5회 이상 로그인 실패 후 성공 로그인 발생
```

### AWS CloudTrail 탐지 결과

```text
[HIGH] Root 계정 콘솔 로그인 성공
이벤트 소스   : signin.amazonaws.com
이벤트 이름   : ConsoleLogin
탐지 사유     : Root 계정으로 AWS 콘솔 로그인이 발생했습니다.
권장 대응     : Root 계정 사용 사유를 확인하고, MFA 적용 및 사용 최소화를 점검합니다.
```

## 분석 흐름

```text
로그 파일 입력
→ 이벤트 파싱
→ IP, 사용자, 이벤트 유형 추출
→ 탐지 기준 적용
→ 위험도와 권장 대응 분류
→ TXT 및 Markdown 리포트 생성
```

## 사용 기술

* Linux
* Bash Shell Script
* Python 3
* AWS CloudTrail
* JSON 로그 분석

## 샘플 로그

| 파일 | 목적 |
|---|---|
| `sample_logs/secure_sample.log` | 기본 SSH 실패 로그인 분석 |
| `sample_logs/normal_login.log` | 정상 로그인 케이스 |
| `sample_logs/brute_force_attack.log` | Brute Force 의심 케이스 |
| `sample_logs/failed_then_success.log` | 반복 실패 후 성공 로그인 케이스 |
| `sample_logs/mixed_case.log` | 여러 유형이 섞인 SSH 로그 케이스 |
| `aws/sample_cloudtrail_logs/cloudtrail_sample.json` | AWS CloudTrail 보안 이벤트 샘플 |

## 보안 관점에서의 의미

SSH 로그인 실패가 반복적으로 발생하는 경우 공격자가 계정 비밀번호를 추측하거나 자동화 도구를 사용해 접근을 시도했을 가능성이 있습니다.

또한 반복 실패 후 성공 로그인이 발생하면 실제 계정 침해 가능성을 추가로 확인해야 합니다. AWS 환경에서는 Root 계정 로그인, MFA 미사용 로그인, 민감한 IAM 변경, SSH 포트 전체 공개가 계정 탈취나 권한 상승으로 이어질 수 있으므로 우선적으로 점검해야 합니다.

## 한계점

현재 버전은 학습 및 포트폴리오 목적의 샘플 탐지 도구입니다.

* SSH 시간 범위 탐지는 1시간 단위로 집계하며, 슬라이딩 윈도우 방식은 아닙니다.
* SSH 로그는 일반적인 Linux 인증 로그 형식을 기준으로 파싱합니다.
* CloudTrail 분석은 샘플 JSON과 주요 보안 이벤트 중심으로 구성되어 있습니다.
* 실제 공격 여부를 확정하지 않고 의심 이벤트로 분류합니다.
* 자동 알림, 티켓 생성, 차단 자동화 기능은 포함되어 있지 않습니다.

## 대응 방안

탐지된 의심 이벤트에 대해서는 다음과 같은 대응을 고려할 수 있습니다.

* 의심 IP 접속 이력 확인
* 계정 로그인 성공 여부와 로그인 위치 확인
* 필요 시 비밀번호 변경 및 SSH Key 기반 인증 전환
* root 계정의 원격 SSH 로그인 비활성화
* SSH 접근 가능 IP 제한
* AWS Root 계정 MFA 적용 여부 확인
* IAM Access Key 생성 및 정책 변경 이력 검토
* 보안 그룹 인바운드 규칙 점검
* 반복 AccessDenied 발생 주체의 자격 증명 오남용 여부 확인

## 향후 개선 사항

* CSV 또는 JSON 형식 결과 저장
* SSH 탐지 기준을 슬라이딩 윈도우 방식으로 개선
* MITRE ATT&CK 기법 매핑 추가
* 이메일 또는 Slack 알림 기능 추가
* 의심 IP 차단 명령어 생성 또는 자동 차단 옵션 추가
* CloudTrail 탐지 룰 외부 설정 파일화
* 테스트 코드 추가

## 프로젝트 의의

이 프로젝트를 통해 Linux와 AWS 환경의 보안 로그를 기반으로 이상 징후를 탐지하고, 탐지 결과를 리포트 형태로 정리하는 과정을 구현했습니다.

단순 문자열 검색에서 끝나지 않고 누적 기준, 시간 범위 기준, 실패 후 성공 로그인, CloudTrail 보안 이벤트를 함께 분석하여 CERT 및 클라우드 보안 관점의 기초적인 탐지/분석 역량을 연습했습니다.
