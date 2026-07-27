import csv
import sys
import subprocess
import json
from datetime import datetime

def query_db(sql):
    result = subprocess.run(
        ["docker", "exec", "-i", "monitoring_postgres", "psql", "-U", "audit_user",
         "-d", "audit_log_db", "-t", "-A", "-F", "|", "-c", sql],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print("DB sorgu hatası:", result.stderr)
        sys.exit(1)
    return [line.split("|") for line in result.stdout.strip().split("\n") if line]


def main(csv_path):
    expected = []
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            expected.append(row)

    total = len(expected)
    print(f"[*] Beklenen komut sayısı: {total}")

    found = 0
    missing = []
    status_mismatches = []
    latencies = []

    for row in expected:
        container_name = row["command"].split()[-1]
        expected_status = row["expected_type"]
        local_ts = float(row["local_timestamp"])

        rows = query_db(
            f"SELECT status, timestamp FROM audit_events WHERE command LIKE '%{container_name}%' ORDER BY id DESC LIMIT 1;"
        )

        if not rows or not rows[0][0]:
            missing.append(container_name)
            continue

        found += 1
        db_status, db_timestamp = rows[0]

        if db_status.strip() != expected_status:
            status_mismatches.append((container_name, expected_status, db_status.strip()))

        try:
            db_dt = datetime.strptime(db_timestamp.strip(), "%Y-%m-%d %H:%M:%S")
            local_dt = datetime.fromtimestamp(local_ts)
            latency = (db_dt - local_dt).total_seconds()
            latencies.append(abs(latency))
        except Exception:
            pass

    completeness = 100 * found / total if total else 0

    print("\n" + "="*50)
    print("BENCHMARK SONUÇLARI")
    print("="*50)
    print(f"Toplam beklenen:     {total}")
    print(f"DB'de bulunan:       {found}")
    print(f"Kayıp:               {len(missing)}")
    print(f"Tamlık oranı:        {completeness:.1f}%")
    print(f"Status uyuşmazlığı:  {len(status_mismatches)}")

    if latencies:
        avg_latency = sum(latencies) / len(latencies)
        max_latency = max(latencies)
        print(f"Ortalama gecikme:    {avg_latency:.2f} saniye")
        print(f"Maksimum gecikme:    {max_latency:.2f} saniye")

    if missing:
        print(f"\n[!] Kaybolan container'lar (ilk 10): {missing[:10]}")

    if status_mismatches:
        print(f"\n[!] Status uyuşmazlıkları (ilk 10):")
        for name, exp, got in status_mismatches[:10]:
            print(f"    {name}: beklenen={exp}, gerçek={got}")

    print("="*50)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Kullanım: python3 benchmark_verify.py <csv_dosyasi>")
        sys.exit(1)
    main(sys.argv[1])
