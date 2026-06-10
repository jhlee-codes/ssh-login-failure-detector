#!/usr/bin/env python3

import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path


DEFAULT_LOG_FILE = "aws/sample_cloudtrail_logs/cloudtrail_sample.json"
DEFAULT_THRESHOLD = 3
RESULT_DIR = Path("result")

SENSITIVE_IAM_EVENTS = {
    "CreateUser",
    "DeleteUser",
    "CreateAccessKey",
    "DeleteAccessKey",
    "AttachUserPolicy",
    "DetachUserPolicy",
    "PutUserPolicy",
    "DeleteUserPolicy",
    "AttachRolePolicy",
    "PutRolePolicy",
    "CreatePolicy",
    "CreatePolicyVersion",
    "SetDefaultPolicyVersion",
    "UpdateAssumeRolePolicy",
}

ACCESS_DENIED_KEYWORDS = {
    "AccessDenied",
    "UnauthorizedOperation",
    "Client.UnauthorizedOperation",
}


def load_cloudtrail_events(log_file: Path):
    with log_file.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if isinstance(data, dict) and isinstance(data.get("Records"), list):
        return data["Records"]

    if isinstance(data, list):
        return data

    raise ValueError("CloudTrail 로그 형식이 올바르지 않습니다. Records 배열이 필요합니다.")


def get_user_name(event: dict) -> str:
    user_identity = event.get("userIdentity", {})

    return (
        user_identity.get("userName")
        or user_identity.get("arn")
        or user_identity.get("principalId")
        or user_identity.get("type")
        or "-"
    )


def get_source_ip(event: dict) -> str:
    return event.get("sourceIPAddress", "-")


def get_event_time(event: dict) -> str:
    return event.get("eventTime", "-")


def add_finding(findings: list, risk: str, title: str, event: dict, reason: str, response: str):
    findings.append(
        {
            "risk": risk,
            "title": title,
            "event_time": get_event_time(event),
            "event_source": event.get("eventSource", "-"),
            "event_name": event.get("eventName", "-"),
            "user": get_user_name(event),
            "source_ip": get_source_ip(event),
            "reason": reason,
            "response": response,
        }
    )


def is_console_login_failure(event: dict) -> bool:
    return (
        event.get("eventName") == "ConsoleLogin"
        and event.get("responseElements", {}).get("ConsoleLogin") == "Failure"
    )


def is_root_login_success(event: dict) -> bool:
    user_identity = event.get("userIdentity", {})

    return (
        event.get("eventName") == "ConsoleLogin"
        and user_identity.get("type") == "Root"
        and event.get("responseElements", {}).get("ConsoleLogin") == "Success"
    )


def is_login_without_mfa(event: dict) -> bool:
    return (
        event.get("eventName") == "ConsoleLogin"
        and event.get("responseElements", {}).get("ConsoleLogin") == "Success"
        and event.get("additionalEventData", {}).get("MFAUsed") == "No"
    )


def is_sensitive_iam_change(event: dict) -> bool:
    return (
        event.get("eventSource") == "iam.amazonaws.com"
        and event.get("eventName") in SENSITIVE_IAM_EVENTS
    )


def extract_ip_permissions(event: dict):
    request_parameters = event.get("requestParameters", {})
    ip_permissions = request_parameters.get("ipPermissions", {})

    if isinstance(ip_permissions, dict):
        return ip_permissions.get("items", [])

    if isinstance(ip_permissions, list):
        return ip_permissions

    return []


def port_in_range(from_port, to_port, target_port: int) -> bool:
    if from_port is None or to_port is None:
        return False

    try:
        return int(from_port) <= target_port <= int(to_port)
    except ValueError:
        return False


def has_world_open_cidr(permission: dict) -> bool:
    ip_ranges = permission.get("ipRanges", {})
    ipv6_ranges = permission.get("ipv6Ranges", {})

    ipv4_items = ip_ranges.get("items", []) if isinstance(ip_ranges, dict) else []
    ipv6_items = ipv6_ranges.get("items", []) if isinstance(ipv6_ranges, dict) else []

    for item in ipv4_items:
        if item.get("cidrIp") == "0.0.0.0/0":
            return True

    for item in ipv6_items:
        if item.get("cidrIpv6") == "::/0":
            return True

    return False


def is_ssh_open_to_world(event: dict) -> bool:
    if event.get("eventName") != "AuthorizeSecurityGroupIngress":
        return False

    for permission in extract_ip_permissions(event):
        protocol = str(permission.get("ipProtocol", ""))
        from_port = permission.get("fromPort")
        to_port = permission.get("toPort")

        if not has_world_open_cidr(permission):
            continue

        if protocol == "-1":
            return True

        if protocol == "tcp" and port_in_range(from_port, to_port, 22):
            return True

    return False


def is_access_denied(event: dict) -> bool:
    error_code = event.get("errorCode", "")

    if not error_code:
        return False

    return any(keyword in error_code for keyword in ACCESS_DENIED_KEYWORDS)


def analyze_cloudtrail(log_file: Path, threshold: int):
    events = load_cloudtrail_events(log_file)
    findings = []

    access_denied_by_ip = Counter()

    for event in events:
        if is_console_login_failure(event):
            add_finding(
                findings,
                "MEDIUM",
                "AWS 콘솔 로그인 실패",
                event,
                "AWS Management Console 로그인 실패 이벤트 발생",
                "사용자, 접속 IP, MFA 사용 여부를 확인합니다.",
            )

        if is_root_login_success(event):
            add_finding(
                findings,
                "HIGH",
                "Root 계정 콘솔 로그인 성공",
                event,
                "Root 계정으로 AWS 콘솔 로그인이 발생했습니다.",
                "Root 계정 사용 사유를 확인하고, MFA 적용 및 사용 최소화를 점검합니다.",
            )

        if is_login_without_mfa(event):
            add_finding(
                findings,
                "HIGH" if event.get("userIdentity", {}).get("type") == "Root" else "MEDIUM",
                "MFA 미사용 콘솔 로그인",
                event,
                "MFA 없이 AWS 콘솔 로그인에 성공했습니다.",
                "MFA 설정 여부를 확인하고, 계정 보안 정책을 점검합니다.",
            )

        if is_sensitive_iam_change(event):
            add_finding(
                findings,
                "HIGH",
                "민감한 IAM 변경 이벤트",
                event,
                f"IAM 관련 민감 이벤트({event.get('eventName')})가 발생했습니다.",
                "변경 주체와 대상 사용자를 확인하고, 권한 상승 또는 지속성 확보 가능성을 점검합니다.",
            )

        if is_ssh_open_to_world(event):
            group_id = event.get("requestParameters", {}).get("groupId", "-")

            add_finding(
                findings,
                "HIGH",
                "SSH 포트 전체 공개",
                event,
                f"보안 그룹({group_id})에서 SSH 22번 포트가 0.0.0.0/0 또는 ::/0에 공개되었습니다.",
                "보안 그룹 인바운드 규칙을 확인하고, SSH 접근 대상을 신뢰 IP로 제한합니다.",
            )

        if is_access_denied(event):
            access_denied_by_ip[get_source_ip(event)] += 1

    for source_ip, count in access_denied_by_ip.items():
        if count >= threshold:
            dummy_event = {
                "eventTime": "-",
                "eventSource": "-",
                "eventName": "AccessDenied",
                "sourceIPAddress": source_ip,
                "userIdentity": {"type": "-"},
            }

            add_finding(
                findings,
                "MEDIUM",
                "반복 AccessDenied 발생",
                dummy_event,
                f"동일 IP에서 AccessDenied 또는 UnauthorizedOperation 이벤트가 {count}회 발생했습니다.",
                "권한 없는 API 호출 반복 여부를 확인하고, 접근 주체와 사용된 자격 증명을 점검합니다.",
            )

    findings.sort(
        key=lambda item: (
            {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(item["risk"], 3),
            item["event_time"],
        )
    )

    return {
        "total_events": len(events),
        "total_findings": len(findings),
        "high_count": sum(1 for item in findings if item["risk"] == "HIGH"),
        "medium_count": sum(1 for item in findings if item["risk"] == "MEDIUM"),
        "findings": findings,
    }


def write_txt_report(result_file: Path, log_file: Path, threshold: int, analysis: dict):
    with result_file.open("w", encoding="utf-8") as report:
        report.write("==================================================\n")
        report.write(" AWS CloudTrail 보안 이벤트 분석 리포트\n")
        report.write("==================================================\n\n")

        report.write("[분석 정보]\n")
        report.write(f"분석 시간      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.write(f"분석 로그 파일 : {log_file}\n")
        report.write(f"반복 실패 기준 : 동일 IP에서 AccessDenied {threshold}회 이상\n\n")

        report.write("--------------------------------------------------\n")
        report.write("[요약]\n")
        report.write(f"전체 이벤트 수 : {analysis['total_events']}\n")
        report.write(f"탐지 이벤트 수 : {analysis['total_findings']}\n")
        report.write(f"HIGH 위험도    : {analysis['high_count']}\n")
        report.write(f"MEDIUM 위험도  : {analysis['medium_count']}\n\n")

        report.write("--------------------------------------------------\n")
        report.write("[탐지 결과]\n")

        if analysis["findings"]:
            for item in analysis["findings"]:
                report.write("\n")
                report.write(f"[{item['risk']}] {item['title']}\n")
                report.write(f"이벤트 시간   : {item['event_time']}\n")
                report.write(f"이벤트 소스   : {item['event_source']}\n")
                report.write(f"이벤트 이름   : {item['event_name']}\n")
                report.write(f"사용자        : {item['user']}\n")
                report.write(f"Source IP     : {item['source_ip']}\n")
                report.write(f"탐지 사유     : {item['reason']}\n")
                report.write(f"권장 대응     : {item['response']}\n")
        else:
            report.write("\n[정상] 탐지된 AWS 보안 이벤트가 없습니다.\n")

        report.write("\n--------------------------------------------------\n")
        report.write("[최종 결과]\n")
        report.write(f"결과 파일 : {result_file}\n")
        report.write("==================================================\n")


def write_markdown_report(markdown_file: Path, log_file: Path, threshold: int, analysis: dict):
    with markdown_file.open("w", encoding="utf-8") as report:
        report.write("# AWS CloudTrail Security Analysis Report\n\n")

        report.write("## 1. Analysis Information\n\n")
        report.write("| 항목 | 값 |\n")
        report.write("|---|---|\n")
        report.write(f"| 분석 시간 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |\n")
        report.write(f"| 분석 로그 파일 | {log_file} |\n")
        report.write(f"| 반복 실패 기준 | 동일 IP에서 AccessDenied {threshold}회 이상 |\n\n")

        report.write("## 2. Summary\n\n")
        report.write("| 항목 | 값 |\n")
        report.write("|---|---:|\n")
        report.write(f"| 전체 이벤트 수 | {analysis['total_events']} |\n")
        report.write(f"| 탐지 이벤트 수 | {analysis['total_findings']} |\n")
        report.write(f"| HIGH 위험도 | {analysis['high_count']} |\n")
        report.write(f"| MEDIUM 위험도 | {analysis['medium_count']} |\n\n")

        report.write("## 3. Detection Results\n\n")
        report.write("| Risk | Title | Event Time | Event Source | Event Name | User | Source IP | Reason | Recommended Response |\n")
        report.write("|---|---|---|---|---|---|---|---|---|\n")

        if analysis["findings"]:
            for item in analysis["findings"]:
                report.write(
                    f"| {item['risk']} | {item['title']} | {item['event_time']} | "
                    f"{item['event_source']} | {item['event_name']} | {item['user']} | "
                    f"{item['source_ip']} | {item['reason']} | {item['response']} |\n"
                )
        else:
            report.write("| INFO | 정상 | - | - | - | - | - | 탐지된 AWS 보안 이벤트 없음 | 추가 조치 불필요 |\n")

        report.write("\n## 4. Detection Rule Summary\n\n")
        report.write("| Rule | Risk | Description |\n")
        report.write("|---|---|---|\n")
        report.write("| ConsoleLogin Failure | MEDIUM | AWS 콘솔 로그인 실패 탐지 |\n")
        report.write("| Root ConsoleLogin Success | HIGH | Root 계정 콘솔 로그인 성공 탐지 |\n")
        report.write("| ConsoleLogin Without MFA | MEDIUM/HIGH | MFA 미사용 콘솔 로그인 탐지 |\n")
        report.write("| Sensitive IAM Change | HIGH | Access Key 생성, 정책 연결 등 IAM 변경 탐지 |\n")
        report.write("| SSH Open to World | HIGH | 보안 그룹에서 SSH 22번 포트 전체 공개 탐지 |\n")
        report.write("| Repeated AccessDenied | MEDIUM | 동일 IP에서 반복적인 권한 거부 이벤트 탐지 |\n\n")

        report.write("## 5. Recommended Response Guide\n\n")
        report.write("- Root 계정 로그인 발생 시 사용 사유와 MFA 적용 여부를 우선 확인합니다.\n")
        report.write("- IAM 정책 변경, Access Key 생성 이벤트는 권한 상승 또는 지속성 확보 가능성을 점검합니다.\n")
        report.write("- SSH 22번 포트가 0.0.0.0/0에 공개된 경우 신뢰 IP로 제한하는 것을 검토합니다.\n")
        report.write("- AccessDenied가 반복되는 IP는 권한 없는 API 호출 또는 자격 증명 오남용 가능성을 확인합니다.\n")


def main():
    log_file = Path(sys.argv[1]) if len(sys.argv) >= 2 else Path(DEFAULT_LOG_FILE)

    try:
        threshold = int(sys.argv[2]) if len(sys.argv) >= 3 else DEFAULT_THRESHOLD
    except ValueError:
        print("Error: THRESHOLD는 숫자로 입력해야 합니다.")
        sys.exit(1)

    if not log_file.exists():
        print(f"Error: CloudTrail 로그 파일이 존재하지 않습니다: {log_file}")
        sys.exit(1)

    RESULT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_file = RESULT_DIR / f"aws_cloudtrail_result_{timestamp}.txt"
    markdown_file = RESULT_DIR / f"aws_cloudtrail_report_{timestamp}.md"

    analysis = analyze_cloudtrail(log_file, threshold)

    write_txt_report(result_file, log_file, threshold, analysis)
    write_markdown_report(markdown_file, log_file, threshold, analysis)

    print(f"분석 완료. TXT 결과 파일: {result_file}")
    print(f"분석 완료. Markdown 리포트 파일: {markdown_file}")


if __name__ == "__main__":
    main()