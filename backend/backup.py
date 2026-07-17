from fastapi import Depends, FastAPI, Response
from datetime import datetime
import re
from sqlalchemy.orm import Session
from database import AuditEvent, get_db, SessionLocal, SystemMetrics
from fastapi.middleware.cors import CORSMiddleware
import time
import asyncio
from collections import deque

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DOCKER_SUBCOMMANDS = {
    "run", "exec", "ps", "start", "stop", "restart", "rm", "rmi",
    "logs", "inspect", "pull", "push", "build", "images", "network",
    "volume", "compose", "stats", "top", "cp", "commit", "save",
    "load", "port", "kill", "pause", "unpause", "wait", "attach",
    "create", "diff", "events", "export", "history", "import",
    "info", "version", "login", "logout", "rename", "search",
    "tag", "update", "prune", "system", "context", "plugin",
    "trust", "manifest", "builder", "buildx", "container", "image",
}

# Pozisyonel argüman ALMAYAN subcommand'ler (sadece flag kabul ederler)
NO_POSITIONAL_ARG_SUBCOMMANDS = {
    "ps", "images", "version", "info", "system", "events", "login", "logout",
}

AUDIT_TIMESTAMP_PATTERN = re.compile(r"msg=audit\((\d+\.\d+):\d+\)")
AUDIT_SUCCESS_PATTERN = re.compile(r"success=(\w+)")
AUDIT_PID_PATTERN = re.compile(r"pid=(\d+)")
AUDIT_EXE_PATTERN = re.compile(r'exe="([^"]+)"')
AUDIT_SYSCALL_PATTERN = re.compile(r"syscall=(\d+)")
ARGC_PATTERN = re.compile(r'argc=(\d+)')

AUDIT_ID_PATTERN = re.compile(r'msg=audit\(([\d.]+:\d+)\)')
AUDIT_UID_PATTERN= re.compile(r'UID="([^"]+)"')


pending_events: dict[str, dict] = {}
FLUSH_TIMEOUT = 1.5

recent_docker_events: deque = deque(maxlen=500)  # zaman damgalı container olayları (double ended queue)
DOCKER_EVENT_MATCH_WINDOW = 3.0  # saniye - audit event ile docker event arasında kabul edilen maksimum fark

REQUIRES_CONTAINER_EVENT_MATCH = {
    "exec", "start", "stop", "restart", "kill", "rm", "logs", "attach", "cp", "pause", "unpause",
}

def is_valid_command(cmd: str) -> bool:
    if not cmd or not cmd.strip():
        return False

    parts = cmd.strip().split()
    if len(parts) < 2:
        return False

    subcommand = parts[1].lower()

    if subcommand not in DOCKER_SUBCOMMANDS:
        return False

    # "ps" gibi komutlarda, flag olmayan (- ile başlamayan)
    # fazladan bir argüman varsa muhtemelen hatalı/anlamsız bir komuttur
    if subcommand in NO_POSITIONAL_ARG_SUBCOMMANDS:
        extra_args = parts[2:]
        for arg in extra_args:
            if not arg.startswith("-"):
                return False  # "docker ps dadwada" gibi -> reddet

    return True

def extract_audit_id(line: str) -> str | None:
    match = AUDIT_ID_PATTERN.search(line)
    return match.group(1) if match else None


def extract_execve(line :str) -> str:
    argc_match = ARGC_PATTERN.search(line)
    if not argc_match:
        return ""
    
    argc = int(argc_match.group(1))
    arguments = []
    
    for i in range(argc):
        arg_match = re.search(rf'a{i}="([^"]*)"', line)
        if arg_match:
            arguments.append(arg_match.group(1))
                        
    return " " .join(arguments).replace('"', '')

    
def parse_log(lines: list[str]) -> dict | None:  
    record = {
        "timestamp": None,
        "_epoch": None, # for container event matching
        "user": "unknown",
        "status": "UNKNOWN",
        "pid": None,
        "executable": "unknown",
        "operation": "EXECUTE/RUN",
        "syscall": "unknown",
        "command": "",
        
    }
    has_execve = False
    has_syscall = False
    
    for line in lines:
        if record["timestamp"] is None:
            ts_match = AUDIT_TIMESTAMP_PATTERN.search(line)
            if ts_match:
                epoch_time = float(ts_match.group(1))
                record["_epoch"] = epoch_time
                record["timestamp"] = datetime.fromtimestamp(epoch_time).strftime(
                 "%Y-%m-%d %H:%M:%S"
                )

                
        if "type=SYSCALL" in line:
            has_syscall = True
            uid_match = AUDIT_UID_PATTERN.search(line)
            success_match = AUDIT_SUCCESS_PATTERN.search(line)
            pid_match = AUDIT_PID_PATTERN.search(line)
            exe_match = AUDIT_EXE_PATTERN.search(line)
            syscall_match = AUDIT_SYSCALL_PATTERN.search(line)

            if success_match:
                record["status"] = "SUCCESS" if success_match.group(1) else "FAILED"
            if uid_match:
                record["user"] = uid_match.group(1)
            if pid_match:
                record["pid"] = int(pid_match.group(1))
            if exe_match:
                record["executable"] = exe_match.group(1)
            if syscall_match:
                record["syscall"] = syscall_match.group(1)
        elif "type=EXECVE" in line:
            has_execve = True
            record["command"] = extract_execve(line)

    combined_text = (record["executable"] or "") + " " + (record["command"] or "")
    if "docker" not in combined_text:
        return None

    if not (has_execve or has_syscall) or record["timestamp"] is None:
        return None

    if not is_valid_command(record["command"]):
        return None
    return record

#check buffer in intervals and save the expired events into the db 
async def flush_loop():
    while True:
        await asyncio.sleep(1)
        now = time.time()
        expired_ids = [
            audit_id for audit_id, data in pending_events.items()
            if now - data["last_seen"] > FLUSH_TIMEOUT
        ]
        for audit_id in expired_ids:
            data = pending_events.pop(audit_id)
            parsed_res = parse_log(data["lines"])

            if parsed_res:
                # Container eşleştirmesi
                container_id = None
                container_name = None
                match = None
                if parsed_res["_epoch"] is not None:
                    match = find_matching_container_event(parsed_res["_epoch"])
                    if match:
                        container_id = match["container_id"]
                        container_name = match["container_name"]

                # Subcommand'i çıkar (örn. "docker exec ..." -> "exec")
                command_parts = (parsed_res["command"] or "").strip().split()
                subcommand = command_parts[1].lower() if len(command_parts) > 1 else ""

                # Bu subcommand container hedefliyorsa ve eşleşme bulunamadıysa,
                # işlem muhtemelen başarısız olmuştur (container yok vb.) -> kaydetme
                if subcommand in REQUIRES_CONTAINER_EVENT_MATCH and not match:
                    print(f"[!] Eşleşen container event bulunamadı, atlanıyor: {parsed_res['command']}", flush=True)
                    continue

                db = SessionLocal()
                try:
                    db_event = AuditEvent(
                        timestamp=parsed_res["timestamp"],
                        user=parsed_res["user"],
                        status=parsed_res["status"],
                        pid=parsed_res["pid"],
                        executable=parsed_res["executable"],
                        operation=parsed_res["operation"],
                        syscall=parsed_res["syscall"],
                        command=parsed_res["command"],
                        container_id=container_id,
                        container_name=container_name,
                    )
                    db.add(db_event)
                    db.commit()
                    print(f"[*] Event kaydedildi (audit_id={audit_id}), container={container_name}", flush=True)
                finally:
                    db.close()

                    
@app.on_event("startup")
async def start_flush_task():
    asyncio.create_task(flush_loop())
    
@app.get("/api/logs")
def get_logs_api(db: Session = Depends(get_db)):
    logs = db.query(AuditEvent).order_by(AuditEvent.id.desc()).limit(50).all()
    return logs

    
@app.get("/")
def read_root():
    return {
        "status": "success",
        "message": "Docker Monitoring backend active\n",
    }

@app.post("/receiver")
def receive_agent_logs(payload: dict):
    raw_log = payload.get("message", "")
    audit_id = extract_audit_id(raw_log)

    if not audit_id:
        return Response(content="audit_id bulunamadı\n", status_code=200)

    if audit_id not in pending_events:
        pending_events[audit_id] = {"lines": [], "last_seen": time.time()}

    pending_events[audit_id]["lines"].append(raw_log)
    pending_events[audit_id]["last_seen"] = time.time()

    return Response(content="Log buffer'a eklendi\n", media_type="text/plain")




# metrics endpoints
@app.post("/api/metrics/ingest")
def ingest_metrics(payload: dict, db: Session = Depends(get_db)):
    now = datetime.now()

    
    db.add(SystemMetrics(
        timestamp=now,
        target_type=payload.get("target_type", "unknown"),
        target_name=payload.get("target_name", "unknown"),
        cpu_usage=payload.get("cpu_usage", 0),
        ram_usage=payload.get("ram_usage", 0),
    ))

    db.commit()
    return {"status": "ok"}


@app.get("/api/metrics/live")
def get_live_metrics(db: Session = Depends(get_db)):
    
    subq = (
        db.query(
            SystemMetrics.target_name,
            SystemMetrics.target_type,
            SystemMetrics.cpu_usage,
            SystemMetrics.ram_usage,
            SystemMetrics.timestamp,
        )
        .order_by(SystemMetrics.timestamp.desc())
        .limit(200)  
        .all()
    )

    latest = {}
    for row in subq:
        key = (row.target_type, row.target_name)
        if key not in latest:
            latest[key] = row

    hosts = []
    containers = []

    
    for (t_type, t_name), row in latest.items():
        entry = {"name": t_name, "cpu": row.cpu_usage, "ram": row.ram_usage, "status": "running"}
        if t_type == "host":
            hosts.append(entry)
        else:
            containers.append(entry)

    hosts.sort(key=lambda h: h["name"])
    containers.sort(key=lambda c: c["name"])
            
    return {"hosts": hosts, "containers": containers}

@app.get("/api/metrics/history")
def get_metrics_history(
    start_date: str = None,
    end_date: str = None,
    server_name: str = None,
    db: Session = Depends(get_db),
):
    query = db.query(SystemMetrics)

    if start_date:
        query = query.filter(SystemMetrics.timestamp >= start_date)
    if end_date:
        query = query.filter(SystemMetrics.timestamp <= end_date)
    if server_name:
        query = query.filter(SystemMetrics.target_name == server_name)
        
    rows = query.order_by(SystemMetrics.timestamp.desc()).limit(500).all()

    host_rows = [
        {"timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S"), "cpu_usage": r.cpu_usage, "ram_usage": r.ram_usage, "name": r.target_name}
        for r in rows if r.target_type == "host"
    ]
    container_rows = [
        {"timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S"), "cpu_usage": r.cpu_usage, "ram_usage": r.ram_usage, "name": r.target_name}
        for r in rows if r.target_type == "container"
    ]
    
    return {"host": host_rows, "containers": container_rows}

@app.post("/api/docker-events/ingest")
def ingest_docker_events(payload: dict):
    recent_docker_events.append({
        "container_id": payload.get("container_id", ""),
        "container_name": payload.get("container_name", "unknown"),
        "action": payload.get("action", "unknown"),
        "event_time": float(payload.get("event_time", time.time())),
    })
    return {"status": "ok"}


def find_matching_container_event(audit_epoch: float) -> dict | None:
    """Audit event'in zaman damgasına en yakın container olayını bulur."""
    best_match = None
    best_diff = DOCKER_EVENT_MATCH_WINDOW

    for event in recent_docker_events:
        diff = abs(event["event_time"] - audit_epoch)
        if diff <= best_diff:
            best_diff = diff
            best_match = event

    return best_match
