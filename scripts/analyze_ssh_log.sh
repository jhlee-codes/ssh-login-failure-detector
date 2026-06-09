#!/bin/bash

LOG_FILE=${1:-sample_logs/secure_sample.log}
THRESHOLD=5
RESULT_DIR="./result"
RESULT_FILE="$RESULT_DIR/ssh_detection_result_$(date +%Y%m%d).txt"

mkdir -p "$RESULT_DIR"

if [ ! -f "$LOG_FILE" ]; then
    echo "Error: 로그 파일이 존재하지 않습니다: $LOG_FILE"
    exit 1
fi

echo "SSH 로그인 실패 탐지 결과" > "$RESULT_FILE"
echo "분석 시간: $(date)" >> "$RESULT_FILE"
echo "탐지 기준: 동일 IP에서 로그인 실패 ${THRESHOLD}회 이상" >> "$RESULT_FILE"
echo "----------------------------------------" >> "$RESULT_FILE"

grep "Failed password" "$LOG_FILE" | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | while read count ip
do
    if [ "$count" -ge "$THRESHOLD" ]; then
        echo "[의심] IP: $ip / 실패 횟수: $count" >> "$RESULT_FILE"
    fi
done

echo "분석 완료. 결과 파일: $RESULT_FILE"