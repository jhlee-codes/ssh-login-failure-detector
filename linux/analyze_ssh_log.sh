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

echo "SSH 로그인 실패 탐지 결과" > "$RESULT_FILE"
echo "분석 시간: $(date)" >> "$RESULT_FILE"
echo "분석 로그 파일: $LOG_FILE" >> "$RESULT_FILE"
echo "탐지 기준: 동일 IP에서 로그인 실패 ${THRESHOLD}회 이상" >> "$RESULT_FILE"
echo "----------------------------------------" >> "$RESULT_FILE"
echo "전체 SSH 로그인 실패 횟수: $total_failed" >> "$RESULT_FILE"
echo "로그인 실패 발생 IP 수: $unique_ips" >> "$RESULT_FILE"
echo "----------------------------------------" >> "$RESULT_FILE"

suspicious_count=0

while read -r count ip
do
    if [ "$count" -ge "$THRESHOLD" ]; then
        echo "[의심] IP: $ip / 실패 횟수: $count" >> "$RESULT_FILE"
        suspicious_count=$((suspicious_count + 1))
    fi
done < <(echo "$failed_ips" | sort ㄴ| uniq -c | sort -nr)

if [ "$suspicious_count" -eq 0 ]; then
    echo "[정상] 임계치 이상 로그인 실패 IP가 없습니다." >> "$RESULT_FILE"
fi

echo "----------------------------------------" >> "$RESULT_FILE"
echo "의심 IP 수: $suspicious_count" >> "$RESULT_FILE"

echo "분석 완료. 결과 파일: $RESULT_FILE"