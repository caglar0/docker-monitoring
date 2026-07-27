#!/bin/bash
# Kullanım: ./benchmark_run.sh <toplam_komut_sayisi>
N=${1:-50}
RUN_ID=$(date +%s)
LOG_FILE="benchmark_${RUN_ID}.csv"

echo "run_id,index,expected_type,command,local_timestamp" > "$LOG_FILE"

echo "[*] Benchmark başlıyor: RUN_ID=$RUN_ID, N=$N komut"

for i in $(seq 1 "$N"); do
    TS=$(date +%s.%N)
    # %3 ihtimalle geçersiz komut üret (FAILED testi için)
    if (( RANDOM % 4 == 0 )); then
        CONTAINER_NAME="bench-${RUN_ID}-invalid-${i}"
        docker run -d --name "$CONTAINER_NAME" nonexistent-image-xyz-${RUN_ID} > /dev/null 2>&1
        echo "${RUN_ID},${i},FAILED,docker run ${CONTAINER_NAME},${TS}" >> "$LOG_FILE"
    else
        CONTAINER_NAME="bench-${RUN_ID}-valid-${i}"
        docker run -d --name "$CONTAINER_NAME" --label owner=benchuser alpine sleep 300 > /dev/null 2>&1
        echo "${RUN_ID},${i},SUCCESS,docker run ${CONTAINER_NAME},${TS}" >> "$LOG_FILE"
    fi

    # Küçük bir gecikme, komutların üst üste binmesini biraz azaltır ama yine de "burst" sayılır
    sleep 0.1
done

echo "[*] Tamamlandı. RUN_ID=$RUN_ID"
echo "[*] Log dosyası: $LOG_FILE"
echo "[*] Bu dosyayı monitor server'a kopyala, sonra doğrulama scriptini çalıştır."


