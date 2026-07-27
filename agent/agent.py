import http.client
import json
import os
import re
import subprocess
import sys
import threading
import time
from urllib.parse import urlparse

LOG_FILE_PATH = "/var/log/audit/audit.log"

MONITOR_HOST = os.getenv("MONITOR_HOST", "http://localhost:8000")
MONITORING_SERVER_URL = f"{MONITOR_HOST}/receiver"
METRICS_URL           = f"{MONITOR_HOST}/api/metrics/ingest"
DOCKER_EVENTS_URL     = f"{MONITOR_HOST}/api/docker-events/ingest"
CONTAINERS_URL        = f"{MONITOR_HOST}/api/containers/ingest"

METRICS_INTERVAL = 10
CONTAINER_INVENTORY_INTERVAL = 15
SERVER_NAME = os.getenv("SERVER_NAME", "gpu-server-unknown")


def post_json(url, data):
    try:
        parsed_url = urlparse(url)
        payload = json.dumps(data)
        headers = {"Content-Type": "application/json"}
        conn_cls = http.client.HTTPSConnection if parsed_url.scheme == "https" else http.client.HTTPConnection
        conn = conn_cls(parsed_url.netloc, timeout=5)
        conn.request("POST", parsed_url.path, payload, headers)
        response = conn.getresponse()
        response.read()
        conn.close()
    except Exception as e:
        print(f"[!] Gönderim hatası ({url}): {e}", file=sys.stderr)


def send_log_to_backend(log_line):
    post_json(MONITORING_SERVER_URL, {"message": log_line})


# ---------- Host Metrikleri ----------

def read_cpu_times():
    with open("/proc/stat") as f:
        line = f.readline()
    parts = [int(x) for x in line.split()[1:]]
    idle = parts[3]
    total = sum(parts)
    return idle, total


def get_host_cpu_percent(prev_idle, prev_total):
    idle, total = read_cpu_times()
    idle_delta = idle - prev_idle
    total_delta = total - prev_total
    cpu_percent = 100 * (1 - idle_delta / total_delta) if total_delta > 0 else 0
    return round(cpu_percent, 1), idle, total


def get_host_ram_info():
    """Yüzde, kullanılan MB, toplam MB döner."""
    meminfo = {}
    with open("/proc/meminfo") as f:
        for line in f:
            key, value = line.split(":")
            meminfo[key.strip()] = int(value.strip().split()[0])  # kB

    total_kb = meminfo.get("MemTotal", 0)
    if "MemAvailable" in meminfo:
        available_kb = meminfo["MemAvailable"]
    else:
        available_kb = meminfo.get("MemFree", 0) + meminfo.get("Buffers", 0) + meminfo.get("Cached", 0)

    used_kb = total_kb - available_kb
    used_percent = 100 * used_kb / total_kb if total_kb > 0 else 0
    return round(used_percent, 1), round(used_kb / 1024, 1), round(total_kb / 1024, 1)


# ---------- MB Parse ----------

def _to_mb(value_str):
    value_str = value_str.strip()
    match = re.match(r"([\d.]+)\s*([KMG]i?B)", value_str, re.IGNORECASE)
    if not match:
        return 0.0
    number, unit = match.groups()
    number = float(number)
    unit = unit.upper()
    if unit in ("KB", "KIB"):
        return round(number / 1024, 2)
    if unit in ("MB", "MIB"):
        return round(number, 2)
    if unit in ("GB", "GIB"):
        return round(number * 1024, 2)
    return round(number, 2)


def parse_mem_usage(mem_usage_str):
    try:
        used_str, limit_str = mem_usage_str.split("/")
        return _to_mb(used_str), _to_mb(limit_str)
    except Exception:
        return 0.0, 0.0


# ---------- Container Metrikleri (docker stats) ----------

def get_container_stats():
    try:
        result = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{json .}}"],
            capture_output=True, text=True, timeout=5
        )
        stats = []
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            data = json.loads(line)
            cpu = float(data["CPUPerc"].replace("%", ""))
            mem_percent = float(data["MemPerc"].replace("%", ""))
            used_mb, total_mb = parse_mem_usage(data.get("MemUsage", "0MiB / 0MiB"))
            stats.append({
                "name": data["Name"],
                "cpu": cpu,
                "ram": mem_percent,
                "ram_mb": used_mb,
                "ram_total_mb": total_mb,
            })
        return stats
    except Exception as e:
        print(f"[!] docker stats okunamadı: {e}", file=sys.stderr)
        return []


def metrics_loop():
    print("[*] Metrics thread başlatıldı.", flush=True)
    prev_idle, prev_total = read_cpu_times()
    while True:
        time.sleep(METRICS_INTERVAL)

        cpu, prev_idle, prev_total = get_host_cpu_percent(prev_idle, prev_total)
        ram_percent, ram_mb, ram_total_mb = get_host_ram_info()
        post_json(METRICS_URL, {
            "target_type": "host",
            "target_name": SERVER_NAME,
            "cpu_usage": cpu,
            "ram_usage": ram_percent,
            "ram_usage_mb": ram_mb,
            "ram_total_mb": ram_total_mb,
        })

        for c in get_container_stats():
            qualified_name = f"{SERVER_NAME}/{c['name']}"
            post_json(METRICS_URL, {
                "target_type": "container",
                "target_name": qualified_name,
                "cpu_usage": c["cpu"],
                "ram_usage": c["ram"],
                "ram_usage_mb": c["ram_mb"],
                "ram_total_mb": c["ram_total_mb"],
            })


# ---------- Docker Events (yaşam döngüsü + owner) ----------

def docker_events_loop():
    while True:
        try:
            proc = subprocess.Popen(
                ["docker", "events", "--format", "{{json .}}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            print("[*] Docker events dinleniyor...", flush=True)
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if data.get("Type") != "container":
                    continue

                actor = data.get("Actor", {})
                attrs = actor.get("Attributes", {})

                event = {
                    "server_name": SERVER_NAME,
                    "container_id": actor.get("ID", "")[:12],
                    "container_name": attrs.get("name", "unknown"),
                    "action": data.get("Action", "unknown"),
                    "event_time": data.get("time"),
                    "owner": attrs.get("owner", "unknown"),
                }
                post_json(DOCKER_EVENTS_URL, event)

        except Exception as e:
            print(f"[!] docker events akışı koptu: {e}", file=sys.stderr, flush=True)

        time.sleep(3)


# ---------- Container Envanteri (docker ps -a, durup çalışanları da yakalar) ----------

def parse_labels(label_str):
    labels = {}
    if not label_str:
        return labels
    for pair in label_str.split(","):
        if "=" in pair:
            k, v = pair.split("=", 1)
            labels[k.strip()] = v.strip()
    return labels


def container_inventory_loop():
    print("[*] Container envanteri thread'i başlatıldı.", flush=True)
    while True:
        try:
            result = subprocess.run(
                ["docker", "ps", "-a", "--format", "{{json .}}"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                data = json.loads(line)
                labels = parse_labels(data.get("Labels", ""))
                post_json(CONTAINERS_URL, {
                    "server_name": SERVER_NAME,
                    "container_id": data.get("ID", ""),
                    "container_name": data.get("Names", "unknown"),
                    "status": data.get("State", "unknown"),
                    "image": data.get("Image", ""),
                    "owner": labels.get("owner", "unknown"),
                })
        except Exception as e:
            print(f"[!] Container envanteri okunamadı: {e}", file=sys.stderr)

        time.sleep(CONTAINER_INVENTORY_INTERVAL)


# ---------- Audit Log İzleme ----------

def watch_audit_log():
    print(f"[*] Docker Agent başlatıldı. İzlenen dosya: {LOG_FILE_PATH}", flush=True)
    if not os.path.exists(LOG_FILE_PATH):
        print(f"[!] HATA: {LOG_FILE_PATH} bulunamadı.", file=sys.stderr)
        sys.exit(1)
    with open(LOG_FILE_PATH, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            log_line = line.strip()
            if log_line and "docker" in log_line:
                send_log_to_backend(log_line)


if __name__ == "__main__":
    threading.Thread(target=metrics_loop, daemon=True).start()
    threading.Thread(target=docker_events_loop, daemon=True).start()
    threading.Thread(target=container_inventory_loop, daemon=True).start()
    watch_audit_log()




