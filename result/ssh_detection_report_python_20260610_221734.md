# SSH Login Failure Detection Report - Python Version

## 1. Analysis Information

| 항목 | 값 |
|---|---|
| 분석 시간 | 2026-06-10 22:17:34 |
| 분석 로그 파일 | sample_logs/secure_sample.log |
| 탐지 기준 | 동일 IP에서 로그인 실패 5회 이상 |
| 시간 범위 기준 | 동일 IP에서 1시간 내 로그인 실패 5회 이상 |

## 2. Summary

| 항목 | 값 |
|---|---:|
| 전체 SSH 로그인 실패 횟수 | 18 |
| 로그인 실패 발생 IP 수 | 3 |
| 전체 누적 의심 IP 수 | 2 |
| 시간 범위 기반 탐지 건수 | 2 |
| 실패 후 성공 로그인 건수 | 0 |

## 3. Detection Results - Cumulative Failed Logins

| Risk | IP Address | Failed Count | Reason | Recommended Response |
|---|---|---:|---|---|
| HIGH | 198.51.100.22 | 11 | 전체 로그 기준 동일 IP에서 로그인 실패 5회 이상 발생 | 방화벽 차단 검토, 계정 로그인 이력 확인, SSH 접근 제한 확인 |
| MEDIUM | 203.0.113.50 | 6 | 전체 로그 기준 동일 IP에서 로그인 실패 5회 이상 발생 | 반복 로그인 실패 여부 모니터링, 접속 출처 확인 |

## 4. Detection Results - Time Window Based Failed Logins

| Risk | Time Window | IP Address | Failed Count | Reason | Recommended Response |
|---|---|---|---:|---|---|
| HIGH | Jun 10 12:00-12:59 | 198.51.100.22 | 11 | 동일 IP에서 1시간 내 로그인 실패 5회 이상 발생 | 단시간 내 집중 공격 가능성이 높으므로 방화벽 차단 및 계정 접근 이력 확인 |
| MEDIUM | Jun 10 12:00-12:59 | 203.0.113.50 | 6 | 동일 IP에서 1시간 내 로그인 실패 5회 이상 발생 | 단시간 반복 실패 여부 모니터링 및 접속 출처 확인 |

## 5. Detection Results - Successful Login After Repeated Failures

| Risk | IP Address | User | Auth Method | Previous Failed Count | Success Time | Reason | Recommended Response |
|---|---|---|---|---:|---|---|---|
| INFO | - | - | - | 0 | - | 반복 실패 후 성공 로그인한 IP 없음 | 추가 조치 불필요 |

## 6. Recommended Response Guide

- 의심 IP의 반복 접속 여부를 추가 확인합니다.
- 실패 후 성공 로그인이 탐지된 경우 해당 계정의 로그인 이력을 우선 확인합니다.
- 필요 시 계정 비밀번호 변경, SSH 접근 제한, 방화벽 차단을 검토합니다.
- 동일 IP에서 반복적인 접근이 지속되면 차단 정책 적용을 검토합니다.
