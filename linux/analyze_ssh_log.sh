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

{
    echo "=================================================="
    echo " SSH 로그인 실패 탐지 리포트"
    echo "=================================================="
    echo
    echo "[분석 정보]"
    echo "분석 시간      : $(date '+%Y-%m-%d %H:%M:%S')"
    echo "분석 로그 파일 : $LOG_FILE"
    echo "탐지 기준      : 동일 IP에서 로그인 실패 ${THRESHOLD}회 이상"
    echo
    echo "--------------------------------------------------"
    echo "[요약]"
    echo "전체 SSH 로그인 실패 횟수 : $total_failed"
    echo "로그인 실패 발생 IP 수   : $unique_ips"
    echo
    echo "--------------------------------------------------"
    echo "[탐지 결과]"
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
            echo "탐지 사유     : 동일 IP에서 로그인 실패 ${THRESHOLD}회 이상 발생"
            echo "권장 대응     : $response"
        } >> "$RESULT_FILE"
    fi
done < <(echo "$failed_ips" | sort | uniq -c | sort -nr)

if [ "$suspicious_count" -eq 0 ]; then
    {
        echo
        echo "[정상] 임계치 이상 로그인 실패 IP가 없습니다."
    } >> "$RESULT_FILE"
fi

{
    echo
    echo "--------------------------------------------------"
    echo "[최종 결과]"
    echo "의심 IP 수 : $suspicious_count"
    echo "결과 파일  : $RESULT_FILE"
    echo "=================================================="
} >> "$RESULT_FILE"

echo "분석 완료. 결과 파일: $RESULT_FILE"