#!/bin/bash

LOG_FILE=${1:-sample_logs/secure_sample.log}
THRESHOLD=${2:-5}
RESULT_DIR="./result"
RESULT_FILE="$RESULT_DIR/ssh_detection_result_$(date +%Y%m%d_%H%M%S).txt"

mkdir -p "$RESULT_DIR"

if [ ! -f "$LOG_FILE" ]; then
    echo "Error: 로그 파일이 존재하지 않습니다: $LOG_FILE"
    exit 1
fi

failed_ips=$(grep "Failed password" "$LOG_FILE" | sed -nE 's/.* from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) port .*/\1/p')

total_failed=$(echo "$failed_ips" | grep -c .)
unique_ips=$(echo "$failed_ips" | sort -u | grep -c .)

suspicious_count=0
time_window_detection_count=0
success_after_failure_count=0

{
    echo "=================================================="
    echo " SSH 로그인 실패 탐지 리포트"
    echo "=================================================="
    echo
    echo "[분석 정보]"
    echo "분석 시간      : $(date '+%Y-%m-%d %H:%M:%S')"
    echo "분석 로그 파일 : $LOG_FILE"
    echo "탐지 기준      : 동일 IP에서 로그인 실패 ${THRESHOLD}회 이상"
    echo "시간 범위 기준 : 동일 IP에서 1시간 내 로그인 실패 ${THRESHOLD}회 이상"
    echo
    echo "--------------------------------------------------"
    echo "[요약]"
    echo "전체 SSH 로그인 실패 횟수 : $total_failed"
    echo "로그인 실패 발생 IP 수   : $unique_ips"
    echo
    echo "--------------------------------------------------"
    echo "[탐지 결과 - 전체 누적 로그인 실패]"
} > "$RESULT_FILE"

while read -r count ip
do
    if [ "$count" -ge "$THRESHOLD" ]; then
        suspicious_count=$((suspicious_count + 1))

        if [ "$count" -ge 10 ]; then
            risk_level="HIGH"
            response="방화벽 차단 검토, 계정 로그인 이력 확인, SSH 접근 제한 확인"
        else
            risk_level="MEDIUM"
            response="반복 로그인 실패 여부 모니터링, 접속 출처 확인"
        fi

        {
            echo
            echo "[$risk_level] 의심 IP 탐지"
            echo "IP 주소       : $ip"
            echo "실패 횟수     : $count"
            echo "탐지 사유     : 전체 로그 기준 동일 IP에서 로그인 실패 ${THRESHOLD}회 이상 발생"
            echo "권장 대응     : $response"
        } >> "$RESULT_FILE"
    fi
done < <(echo "$failed_ips" | sort | uniq -c | sort -nr)

if [ "$suspicious_count" -eq 0 ]; then
    {
        echo
        echo "[정상] 전체 누적 기준 임계치 이상 로그인 실패 IP가 없습니다."
    } >> "$RESULT_FILE"
fi

{
    echo
    echo "--------------------------------------------------"
    echo "[탐지 결과 - 시간 범위 기반 로그인 실패]"
} >> "$RESULT_FILE"

while IFS='|' read -r time_window ip count
do
    if [ -n "$ip" ]; then
        time_window_detection_count=$((time_window_detection_count + 1))

        if [ "$count" -ge 10 ]; then
            risk_level="HIGH"
            response="단시간 내 집중 공격 가능성이 높으므로 방화벽 차단 및 계정 접근 이력 확인"
        else
            risk_level="MEDIUM"
            response="단시간 반복 실패 여부 모니터링 및 접속 출처 확인"
        fi

        {
            echo
            echo "[$risk_level] 시간 범위 기반 의심 IP 탐지"
            echo "IP 주소       : $ip"
            echo "시간 범위     : $time_window"
            echo "실패 횟수     : $count"
            echo "탐지 사유     : 동일 IP에서 1시간 내 로그인 실패 ${THRESHOLD}회 이상 발생"
            echo "권장 대응     : $response"
        } >> "$RESULT_FILE"
    fi
done < <(
    awk -v threshold="$THRESHOLD" '
    /Failed password/ {
        ip = ""

        for (i = 1; i <= NF; i++) {
            if ($i == "from" && $(i+2) == "port") {
                ip = $(i+1)
                break
            }
        }

        if (ip != "") {
            hour = substr($3, 1, 2)
            time_window = $1 " " $2 " " hour ":00-" hour ":59"
            key = time_window "|" ip
            fail_count[key]++
        }
    }

    END {
        for (key in fail_count) {
            if (fail_count[key] >= threshold) {
                print key "|" fail_count[key]
            }
        }
    }
    ' "$LOG_FILE" | sort -t'|' -k1,1 -k3,3nr
)

if [ "$time_window_detection_count" -eq 0 ]; then
    {
        echo
        echo "[정상] 1시간 기준 임계치 이상 로그인 실패 IP가 없습니다."
    } >> "$RESULT_FILE"
fi

{
    echo
    echo "--------------------------------------------------"
    echo "[탐지 결과 - 실패 후 성공 로그인]"
} >> "$RESULT_FILE"

while IFS='|' read -r ip user method fail_count login_time
do
    if [ -n "$ip" ]; then
        success_after_failure_count=$((success_after_failure_count + 1))

        {
            echo
            echo "[HIGH] 실패 후 성공 로그인 탐지"
            echo "IP 주소       : $ip"
            echo "성공 계정     : $user"
            echo "인증 방식     : $method"
            echo "이전 실패 횟수 : $fail_count"
            echo "성공 시간     : $login_time"
            echo "탐지 사유     : 동일 IP에서 ${THRESHOLD}회 이상 로그인 실패 후 성공 로그인 발생"
            echo "권장 대응     : 해당 계정 로그인 이력 확인, 비밀번호 변경 검토, 접속 IP 신뢰 여부 확인"
        } >> "$RESULT_FILE"
    fi
done < <(
    awk -v threshold="$THRESHOLD" '
    /Failed password/ {
        ip = ""

        for (i = 1; i <= NF; i++) {
            if ($i == "from" && $(i+2) == "port") {
                ip = $(i+1)
                break
            }
        }

        if (ip != "") {
            fail_count[ip]++
        }
    }

    /Accepted (password|publickey)/ {
        ip = ""
        user = "-"
        method = "-"
        login_time = $1 " " $2 " " $3

        for (i = 1; i <= NF; i++) {
            if ($i == "Accepted") {
                method = $(i+1)
            }

            if ($i == "for") {
                user = $(i+1)
            }

            if ($i == "from" && $(i+2) == "port") {
                ip = $(i+1)
            }
        }

        if (ip != "" && fail_count[ip] >= threshold && reported[ip] != 1) {
            print ip "|" user "|" method "|" fail_count[ip] "|" login_time
            reported[ip] = 1
        }
    }
    ' "$LOG_FILE"
)

if [ "$success_after_failure_count" -eq 0 ]; then
    {
        echo
        echo "[정상] 반복 실패 후 성공 로그인한 IP가 없습니다."
    } >> "$RESULT_FILE"
fi

{
    echo
    echo "--------------------------------------------------"
    echo "[최종 결과]"
    echo "전체 누적 의심 IP 수       : $suspicious_count"
    echo "시간 범위 기반 탐지 건수   : $time_window_detection_count"
    echo "실패 후 성공 로그인 건수   : $success_after_failure_count"
    echo "결과 파일                  : $RESULT_FILE"
    echo "=================================================="
} >> "$RESULT_FILE"

echo "분석 완료. 결과 파일: $RESULT_FILE"