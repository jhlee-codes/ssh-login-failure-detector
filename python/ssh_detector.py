#!/usr/bin/env python3

import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path


DEFAULT_LOG_FILE = "sample_logs/secure_sample.log"
DEFAULT_THRESHOLD = 5
RESULT_DIR = Path("result")


FAILED_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*"
    r"Failed password.* from (?P<ip>(?:\d{1,3}\.){3}\d{1,3}) port"
)

ACCEPTED_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*"
    r"Accepted (?P<method>password|publickey) for (?P<user>\S+) "
    r"from (?P<ip>(?:\d{1,3}\.){3}\d{1,3}) port"
)


def get_risk_level(count: int) -> str:
    if count >= 10:
        return "HIGH"
    return "MEDIUM"


def get_cumulative_response(count: int) -> str:
    if count >= 10:
        return "방화벽 차단 검토, 계정 로그인 이력 확인, SSH 접근 제한 확인"
    return "반복 로그인 실패 여부 모니터링, 접속 출처 확인"


def get_time_window_response(count: int) -> str:
    if count >= 10:
        return "단시간 내 집중 공격 가능성이 높으므로 방화벽 차단 및 계정 접근 이력 확인"
    return "단시간 반복 실패 여부 모니터링 및 접속 출처 확인"


def parse_failed_log(line: str):
    match = FAILED_PATTERN.search(line)
    if not match:
        return None

    month = match.group("month")
    day = match.group("day")
    log_time = match.group("time")
    ip = match.group("ip")
    hour = log_time[:2]

    return {
        "month": month,
        "day": day,
        "time": log_time,
        "hour": hour,
        "ip": ip,
        "time_window": f"{month} {day} {hour}:00-{hour}:59",
    }


def parse_accepted_log(line: str):
    match = ACCEPTED_PATTERN.search(line)
    if not match:
        return None

    return {
        "month": match.group("month"),
        "day": match.group("day"),
        "time": match.group("time"),
        "method": match.group("method"),
        "user": match.group("user"),
        "ip": match.group("ip"),
        "login_time": f"{match.group('month')} {match.group('day')} {match.group('time')}",
    }


def analyze_log(log_file: Path, threshold: int):
    failed_by_ip = Counter()
    failed_by_time_window = Counter()
    success_after_failures = []

    running_failed_count = Counter()
    reported_success_ip = set()

    with log_file.open("r", encoding="utf-8") as file:
        for line in file:
            failed_log = parse_failed_log(line)

            if failed_log:
                ip = failed_log["ip"]
                time_window = failed_log["time_window"]

                failed_by_ip[ip] += 1
                failed_by_time_window[(time_window, ip)] += 1
                running_failed_count[ip] += 1
                continue

            accepted_log = parse_accepted_log(line)

            if accepted_log:
                ip = accepted_log["ip"]

                if running_failed_count[ip] >= threshold and ip not in reported_success_ip:
                    success_after_failures.append(
                        {
                            "ip": ip,
                            "user": accepted_log["user"],
                            "method": accepted_log["method"],
                            "failed_count": running_failed_count[ip],
                            "login_time": accepted_log["login_time"],
                        }
                    )
                    reported_success_ip.add(ip)

    cumulative_detections = []
    for ip, count in failed_by_ip.most_common():
        if count >= threshold:
            cumulative_detections.append(
                {
                    "risk": get_risk_level(count),
                    "ip": ip,
                    "count": count,
                    "reason": f"전체 로그 기준 동일 IP에서 로그인 실패 {threshold}회 이상 발생",
                    "response": get_cumulative_response(count),
                }
            )

    time_window_detections = []
    for (time_window, ip), count in failed_by_time_window.items():
        if count >= threshold:
            time_window_detections.append(
                {
                    "risk": get_risk_level(count),
                    "time_window": time_window,
                    "ip": ip,
                    "count": count,
                    "reason": f"동일 IP에서 1시간 내 로그인 실패 {threshold}회 이상 발생",
                    "response": get_time_window_response(count),
                }
            )

    time_window_detections.sort(
        key=lambda item: (item["time_window"], -item["count"], item["ip"])
    )

    return {
        "total_failed": sum(failed_by_ip.values()),
        "unique_failed_ips": len(failed_by_ip),
        "cumulative_detections": cumulative_detections,
        "time_window_detections": time_window_detections,
        "success_after_failures": success_after_failures,
    }


def write_txt_report(result_file: Path, log_file: Path, threshold: int, analysis: dict):
    with result_file.open("w", encoding="utf-8") as report:
        report.write("==================================================\n")
        report.write(" SSH 로그인 실패 탐지 리포트 - Python Version\n")
        report.write("==================================================\n\n")

        report.write("[분석 정보]\n")
        report.write(f"분석 시간      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.write(f"분석 로그 파일 : {log_file}\n")
        report.write(f"탐지 기준      : 동일 IP에서 로그인 실패 {threshold}회 이상\n")
        report.write(f"시간 범위 기준 : 동일 IP에서 1시간 내 로그인 실패 {threshold}회 이상\n\n")

        report.write("--------------------------------------------------\n")
        report.write("[요약]\n")
        report.write(f"전체 SSH 로그인 실패 횟수 : {analysis['total_failed']}\n")
        report.write(f"로그인 실패 발생 IP 수   : {analysis['unique_failed_ips']}\n\n")

        report.write("--------------------------------------------------\n")
        report.write("[탐지 결과 - 전체 누적 로그인 실패]\n")

        if analysis["cumulative_detections"]:
            for item in analysis["cumulative_detections"]:
                report.write("\n")
                report.write(f"[{item['risk']}] 의심 IP 탐지\n")
                report.write(f"IP 주소       : {item['ip']}\n")
                report.write(f"실패 횟수     : {item['count']}\n")
                report.write(f"탐지 사유     : {item['reason']}\n")
                report.write(f"권장 대응     : {item['response']}\n")
        else:
            report.write("\n[정상] 전체 누적 기준 임계치 이상 로그인 실패 IP가 없습니다.\n")

        report.write("\n--------------------------------------------------\n")
        report.write("[탐지 결과 - 시간 범위 기반 로그인 실패]\n")

        if analysis["time_window_detections"]:
            for item in analysis["time_window_detections"]:
                report.write("\n")
                report.write(f"[{item['risk']}] 시간 범위 기반 의심 IP 탐지\n")
                report.write(f"IP 주소       : {item['ip']}\n")
                report.write(f"시간 범위     : {item['time_window']}\n")
                report.write(f"실패 횟수     : {item['count']}\n")
                report.write(f"탐지 사유     : {item['reason']}\n")
                report.write(f"권장 대응     : {item['response']}\n")
        else:
            report.write("\n[정상] 1시간 기준 임계치 이상 로그인 실패 IP가 없습니다.\n")

        report.write("\n--------------------------------------------------\n")
        report.write("[탐지 결과 - 실패 후 성공 로그인]\n")

        if analysis["success_after_failures"]:
            for item in analysis["success_after_failures"]:
                report.write("\n")
                report.write("[HIGH] 실패 후 성공 로그인 탐지\n")
                report.write(f"IP 주소       : {item['ip']}\n")
                report.write(f"성공 계정     : {item['user']}\n")
                report.write(f"인증 방식     : {item['method']}\n")
                report.write(f"이전 실패 횟수 : {item['failed_count']}\n")
                report.write(f"성공 시간     : {item['login_time']}\n")
                report.write(f"탐지 사유     : 동일 IP에서 {threshold}회 이상 로그인 실패 후 성공 로그인 발생\n")
                report.write("권장 대응     : 해당 계정 로그인 이력 확인, 비밀번호 변경 검토, 접속 IP 신뢰 여부 확인\n")
        else:
            report.write("\n[정상] 반복 실패 후 성공 로그인한 IP가 없습니다.\n")

        report.write("\n--------------------------------------------------\n")
        report.write("[최종 결과]\n")
        report.write(f"전체 누적 의심 IP 수       : {len(analysis['cumulative_detections'])}\n")
        report.write(f"시간 범위 기반 탐지 건수   : {len(analysis['time_window_detections'])}\n")
        report.write(f"실패 후 성공 로그인 건수   : {len(analysis['success_after_failures'])}\n")
        report.write(f"결과 파일                  : {result_file}\n")
        report.write("==================================================\n")


def write_markdown_report(markdown_file: Path, log_file: Path, threshold: int, analysis: dict):
    with markdown_file.open("w", encoding="utf-8") as report:
        report.write("# SSH Login Failure Detection Report - Python Version\n\n")

        report.write("## 1. Analysis Information\n\n")
        report.write("| 항목 | 값 |\n")
        report.write("|---|---|\n")
        report.write(f"| 분석 시간 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |\n")
        report.write(f"| 분석 로그 파일 | {log_file} |\n")
        report.write(f"| 탐지 기준 | 동일 IP에서 로그인 실패 {threshold}회 이상 |\n")
        report.write(f"| 시간 범위 기준 | 동일 IP에서 1시간 내 로그인 실패 {threshold}회 이상 |\n\n")

        report.write("## 2. Summary\n\n")
        report.write("| 항목 | 값 |\n")
        report.write("|---|---:|\n")
        report.write(f"| 전체 SSH 로그인 실패 횟수 | {analysis['total_failed']} |\n")
        report.write(f"| 로그인 실패 발생 IP 수 | {analysis['unique_failed_ips']} |\n")
        report.write(f"| 전체 누적 의심 IP 수 | {len(analysis['cumulative_detections'])} |\n")
        report.write(f"| 시간 범위 기반 탐지 건수 | {len(analysis['time_window_detections'])} |\n")
        report.write(f"| 실패 후 성공 로그인 건수 | {len(analysis['success_after_failures'])} |\n\n")

        report.write("## 3. Detection Results - Cumulative Failed Logins\n\n")
        report.write("| Risk | IP Address | Failed Count | Reason | Recommended Response |\n")
        report.write("|---|---|---:|---|---|\n")

        if analysis["cumulative_detections"]:
            for item in analysis["cumulative_detections"]:
                report.write(
                    f"| {item['risk']} | {item['ip']} | {item['count']} | "
                    f"{item['reason']} | {item['response']} |\n"
                )
        else:
            report.write("| INFO | - | 0 | 전체 누적 기준 임계치 이상 로그인 실패 IP 없음 | 추가 조치 불필요 |\n")

        report.write("\n## 4. Detection Results - Time Window Based Failed Logins\n\n")
        report.write("| Risk | Time Window | IP Address | Failed Count | Reason | Recommended Response |\n")
        report.write("|---|---|---|---:|---|---|\n")

        if analysis["time_window_detections"]:
            for item in analysis["time_window_detections"]:
                report.write(
                    f"| {item['risk']} | {item['time_window']} | {item['ip']} | {item['count']} | "
                    f"{item['reason']} | {item['response']} |\n"
                )
        else:
            report.write("| INFO | - | - | 0 | 1시간 기준 임계치 이상 로그인 실패 IP 없음 | 추가 조치 불필요 |\n")

        report.write("\n## 5. Detection Results - Successful Login After Repeated Failures\n\n")
        report.write("| Risk | IP Address | User | Auth Method | Previous Failed Count | Success Time | Reason | Recommended Response |\n")
        report.write("|---|---|---|---|---:|---|---|---|\n")

        if analysis["success_after_failures"]:
            for item in analysis["success_after_failures"]:
                report.write(
                    f"| HIGH | {item['ip']} | {item['user']} | {item['method']} | "
                    f"{item['failed_count']} | {item['login_time']} | "
                    f"동일 IP에서 {threshold}회 이상 로그인 실패 후 성공 로그인 발생 | "
                    f"해당 계정 로그인 이력 확인, 비밀번호 변경 검토, 접속 IP 신뢰 여부 확인 |\n"
                )
        else:
            report.write("| INFO | - | - | - | 0 | - | 반복 실패 후 성공 로그인한 IP 없음 | 추가 조치 불필요 |\n")

        report.write("\n## 6. Recommended Response Guide\n\n")
        report.write("- 의심 IP의 반복 접속 여부를 추가 확인합니다.\n")
        report.write("- 실패 후 성공 로그인이 탐지된 경우 해당 계정의 로그인 이력을 우선 확인합니다.\n")
        report.write("- 필요 시 계정 비밀번호 변경, SSH 접근 제한, 방화벽 차단을 검토합니다.\n")
        report.write("- 동일 IP에서 반복적인 접근이 지속되면 차단 정책 적용을 검토합니다.\n")


def main():
    log_file = Path(sys.argv[1]) if len(sys.argv) >= 2 else Path(DEFAULT_LOG_FILE)

    try:
        threshold = int(sys.argv[2]) if len(sys.argv) >= 3 else DEFAULT_THRESHOLD
    except ValueError:
        print("Error: THRESHOLD는 숫자로 입력해야 합니다.")
        sys.exit(1)

    if not log_file.exists():
        print(f"Error: 로그 파일이 존재하지 않습니다: {log_file}")
        sys.exit(1)

    RESULT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_file = RESULT_DIR / f"ssh_detection_result_python_{timestamp}.txt"
    markdown_file = RESULT_DIR / f"ssh_detection_report_python_{timestamp}.md"

    analysis = analyze_log(log_file, threshold)

    write_txt_report(result_file, log_file, threshold, analysis)
    write_markdown_report(markdown_file, log_file, threshold, analysis)

    print(f"분석 완료. TXT 결과 파일: {result_file}")
    print(f"분석 완료. Markdown 리포트 파일: {markdown_file}")


if __name__ == "__main__":
    main()