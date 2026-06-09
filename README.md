# SSH Login Failure Detector

Linux SSH 인증 로그를 분석하여 반복적인 로그인 실패가 발생한 IP를 탐지하는 Bash 기반 보안 로그 분석 프로젝트입니다.

동일 IP에서 SSH 로그인 실패가 일정 횟수 이상 발생하면 SSH Brute Force 의심 행위로 판단하고, 탐지 결과를 텍스트 파일로 저장합니다.

## 프로젝트 목적

이 프로젝트는 로그 분석, 이상 징후 탐지, 사고 판단 및 대응 방안 정리 과정을 연습하기 위해 진행했습니다.

주요 목적은 다음과 같습니다.

* Linux 인증 로그 구조 이해
* SSH 로그인 실패 로그 분석
* Brute Force 의심 행위 탐지
* Bash Shell Script를 활용한 보안 자동화
* 분석 결과를 보고서 형태로 정리하는 연습

## 프로젝트 구조

```text
ssh-login-failure-detector/
├── README.md
├── scripts/
│   └── analyze_ssh_log.sh
├── sample_logs/
│   └── secure_sample.log
├── result/
│   └── .gitkeep
└── report/
    └── incident_report.md
```

## 주요 기능

### 1. SSH 로그인 실패 로그 탐지

로그 파일에서 `Failed password` 문자열을 기준으로 SSH 로그인 실패 기록을 추출합니다.

### 2. IP별 실패 횟수 집계

로그에서 접속 시도 IP를 추출한 뒤, IP별 로그인 실패 횟수를 계산합니다.

### 3. 의심 IP 분류

동일 IP에서 로그인 실패가 5회 이상 발생하면 SSH Brute Force 의심 IP로 분류합니다.

### 4. 탐지 결과 파일 생성

분석 결과는 `result` 디렉터리에 텍스트 파일로 저장됩니다.

## 탐지 기준

| 항목     | 기준                    |
| ------ | --------------------- |
| 탐지 대상  | SSH 로그인 실패 로그         |
| 탐지 키워드 | `Failed password`     |
| 판단 기준  | 동일 IP에서 로그인 실패 5회 이상  |
| 판단 결과  | SSH Brute Force 의심 IP |

## 실행 방법

### 1. 실행 권한 부여

```bash
chmod +x scripts/analyze_ssh_log.sh
```

### 2. 샘플 로그 분석

```bash
./scripts/analyze_ssh_log.sh
```

기본적으로 `sample_logs/secure_sample.log` 파일을 분석합니다.

### 3. 실제 Linux 로그 분석

Rocky Linux, CentOS 계열에서는 SSH 인증 로그가 일반적으로 `/var/log/secure`에 저장됩니다.

```bash
sudo ./scripts/analyze_ssh_log.sh /var/log/secure
```

Ubuntu 계열에서는 `/var/log/auth.log`를 사용할 수 있습니다.

```bash
sudo ./scripts/analyze_ssh_log.sh /var/log/auth.log
```

## 실행 결과 예시

```text
SSH 로그인 실패 탐지 결과
분석 시간: Tue Jun  9 21:22:54 KST 2026
탐지 기준: 동일 IP에서 로그인 실패 5회 이상
----------------------------------------
[의심] IP: 192.168.56.101 / 실패 횟수: 5
```

위 결과는 `192.168.56.101` IP에서 SSH 로그인 실패가 5회 발생했으며, 설정한 탐지 기준에 따라 Brute Force 의심 IP로 분류되었음을 의미합니다.

## 분석 흐름

```text
로그 파일 입력
→ Failed password 로그 추출
→ 접속 IP 추출
→ IP별 실패 횟수 집계
→ 임계치 이상 IP 탐지
→ 결과 파일 생성
```

## 사용 기술

* Linux
* Bash Shell Script

## 주요 활용 명령어

| 명령어 | 사용 목적 |
|---|---|
| grep | `Failed password` 로그 추출 |
| awk | 접속 시도 IP 추출 |
| sort | IP 목록 정렬 |
| uniq | IP별 로그인 실패 횟수 집계 |

## 보안 관점에서의 의미

SSH 로그인 실패가 반복적으로 발생하는 경우, 공격자가 계정 비밀번호를 추측하거나 자동화 도구를 사용해 접근을 시도했을 가능성이 있습니다.

본 프로젝트에서는 이러한 행위를 로그 기반으로 탐지하고, 의심 IP를 식별하는 과정을 구현했습니다.

## 한계점

현재 버전은 전체 로그를 기준으로 IP별 로그인 실패 횟수를 집계합니다.

따라서 다음과 같은 한계가 있습니다.

* 특정 시간 범위 내 발생 횟수를 기준으로 탐지하지 않음
* 실패 후 성공 로그인 여부를 함께 분석하지 않음
* 실제 공격 여부를 확정하지 않고 의심 행위로만 분류함
* 자동 알림 기능은 포함되어 있지 않음

## 대응 방안

탐지된 의심 IP에 대해서는 다음과 같은 대응을 고려할 수 있습니다.

* 의심 IP 차단
* root 계정의 원격 SSH 로그인 비활성화
* 비밀번호 인증 대신 SSH Key 기반 인증 사용
* 로그인 실패 횟수 제한 설정
* fail2ban과 같은 자동 차단 도구 적용
* 주기적인 인증 로그 모니터링


## 향후 개선 사항

* cron을 이용한 주기적 자동 실행
* CSV 형식 결과 저장
* 특정 시간 범위 기준 탐지 기능 추가
* 실패 후 성공 로그인 탐지 기능 추가
* 이메일 또는 메신저 알림 기능 추가
* 의심 IP 자동 차단 기능 추가
* MITRE ATT&CK 기법 매핑 추가

## 프로젝트 의의

이 프로젝트를 통해 Linux 인증 로그를 기반으로 보안 이벤트를 분석하고, 반복적인 로그인 실패 행위를 탐지하는 과정을 경험했습니다.

단순히 로그를 조회하는 것에서 끝나지 않고, 탐지 기준을 설정하고 결과를 보고서 형태로 정리함으로써 CERT 직무에서 필요한 기초적인 로그 분석 및 사고 대응 역량을 연습했습니다.
