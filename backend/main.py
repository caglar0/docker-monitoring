from fastapi import Depends, FastAPI, Response, HTTPException, Header
from datetime import datetime, timedelta
import re
from sqlalchemy.orm import Session
from database import AuditEvent, SystemMetrics, ContainerInfo, ContainerEvent, get_db, SessionLocal
from fastapi.middleware.cors import CORSMiddleware
import time
import asyncio
from collections import deque
import os
import jwt


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin")
JWT_SECRET = os.getenv("JWT_SECRET", "insecure-default-change-me")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 72


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

NO_POSITIONAL_ARG_SUBCOMMANDS = {
    "ps", "images", "version", "info", "system", "events", "login", "logout",
}

OWNER_ASSIGNING_SUBCOMMANDS = {"run", "create"}

AUDIT_TIMESTAMP_PATTERN = re.compile(r"msg=audit\((\d+\.\d+):\d+\)")
AUDIT_SUCCESS_PATTERN = re.compile(r"success=(\w+)")
AUDIT_PID_PATTERN = re.compile(r"pid=(\d+)")
AUDIT_EXE_PATTERN = re.compile(r'exe="([^"]+)"')
AUDIT_SYSCALL_PATTERN = re.compile(r"syscall=(\d+)")
ARGC_PATTERN = re.compile(r'argc=(\d+)')
AUDIT_ID_PATTERN = re.compile(r'msg=audit\(([\d.]+:\d+)\)')
AUDIT_UID_PATTERN = re.compile(r'UID="([^"]+)"')

pending_events: dict[str, dict] = {}
FLUSH_TIMEOUT = 1.5

recent_docker_events: deque = deque(maxlen=500)
DOCKER_EVENT_MATCH_WINDOW = 3.0

REQUIRES_CONTAINER_EVENT_MATCH = {
    "exec", "start", "stop", "restart", "kill", "rm", "logs", "attach", "cp", "pause", "unpause",
}

NOISE_SUBCOMMANDS = {
    "info", "version"
}

# Yetkisiz erişim kontrolü uygulanacak subcommand'ler
OWNERSHIP_SENSITIVE_SUBCOMMANDS = {
    "exec", "start", "stop", "restart", "kill", "rm", "logs", "attach", "cp", "pause", "unpause",
}

def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(authorization: str = Header(None)):
    """Korumalı endpoint'ler için dependency. Authorization: Bearer <token> bekler."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token bulunamadı")

    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token süresi doldu")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Geçersiz token")


@app.post("/api/auth/login")
def login(payload: dict):
    username = payload.get("username", "")
    password = payload.get("password", "")

    if username != ADMIN_USERNAME or password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Kullanıcı adı veya şifre hatalı")

    token = create_token(username)
    return {"token": token, "username": username}



def is_valid_command(cmd: str) -> bool:
    if not cmd or not cmd.strip():
        return False
    parts = cmd.strip().split()
    if len(parts) < 2:
        return False
    subcommand = parts[1].lower()
    if subcommand in NOISE_SUBCOMMANDS:
        return False  
    
    if subcommand not in DOCKER_SUBCOMMANDS:
        return False
    
    if subcommand in NO_POSITIONAL_ARG_SUBCOMMANDS:
        extra_args = parts[2:]
        for arg in extra_args:
            if not arg.startswith("-"):
                return False
    return True


def extract_audit_id(line: str) -> str | None:
    match = AUDIT_ID_PATTERN.search(line)
    return match.group(1) if match else None


def extract_execve(line: str) -> str:
    argc_match = ARGC_PATTERN.search(line)
    if not argc_match:
        return ""
    argc = int(argc_match.group(1))
    arguments = []
    for i in range(argc):
        arg_match = re.search(rf'a{i}="([^"]*)"', line)
        if arg_match:
            arguments.append(arg_match.group(1))
    return " ".join(arguments).replace('"', '')


def parse_log(lines: list[str]) -> dict | None:
    record = {
        "timestamp": None,
        "_epoch": None,
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
                record["timestamp"] = datetime.fromtimestamp(epoch_time).strftime("%Y-%m-%d %H:%M:%S")

        if "type=SYSCALL" in line:
            has_syscall = True
            uid_match = AUDIT_UID_PATTERN.search(line)
            success_match = AUDIT_SUCCESS_PATTERN.search(line)
            pid_match = AUDIT_PID_PATTERN.search(line)
            exe_match = AUDIT_EXE_PATTERN.search(line)
            syscall_match = AUDIT_SYSCALL_PATTERN.search(line)

            if success_match:
                record["status"] = "SUCCESS" if success_match.group(1) == "yes" else "FAILED"
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


def find_matching_container_event(audit_epoch: float) -> dict | None:
    best_match = None
    best_diff = DOCKER_EVENT_MATCH_WINDOW
    for event in recent_docker_events:
        diff = abs(event["event_time"] - audit_epoch)
        if diff <= best_diff:
            best_diff = diff
            best_match = event
    return best_match


def check_unauthorized_access(db: Session, container_id: str, container_name: str, acting_user: str) -> bool:
    """Container'ın sahibi ile işlemi yapan kullanıcı farklıysa True döner."""
    if not container_id and not container_name:
        return False

    info = None
    if container_id:
        info = db.query(ContainerInfo).filter(ContainerInfo.container_id == container_id).first()
    if info is None and container_name:
        info = db.query(ContainerInfo).filter(ContainerInfo.container_name == container_name).first()

    if not info or not info.owner or info.owner == "unknown":
        return False  

    return info.owner != acting_user


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
                container_id = None
                container_name = None
                match = None
                if parsed_res["_epoch"] is not None:
                    match = find_matching_container_event(parsed_res["_epoch"])
                    if match:
                        container_id = match["container_id"]
                        container_name = match["container_name"]

                command_parts = (parsed_res["command"] or "").strip().split()
                subcommand = command_parts[1].lower() if len(command_parts) > 1 else ""

                if subcommand in REQUIRES_CONTAINER_EVENT_MATCH and not match:
                    print(f"[!] Eşleşen container event bulunamadı, atlanıyor: {parsed_res['command']}", flush=True)
                    continue

                db = SessionLocal()
                try:
                    # --- YENİ: docker run/create ile container oluşturulduysa, komutu çalıştıran kullanıcıyı owner yap ---
                    if subcommand in OWNER_ASSIGNING_SUBCOMMANDS and container_id:
                        info = db.query(ContainerInfo).filter(ContainerInfo.container_id == container_id).first()
                        if info is None:
                            info = ContainerInfo(
                                container_id=container_id,
                                container_name=container_name or "unknown",
                                owner=parsed_res["user"],
                                status="running",
                                server_name="unknown",
                                last_seen=datetime.now(),
                            )
                            db.add(info)
                        elif not info.owner or info.owner == "unknown":
                            info.owner = parsed_res["user"]
                            db.commit()
                            print(f"[*] Container owner atandı: {container_name} -> {parsed_res['user']}", flush=True)

                    unauthorized = False
                    if subcommand in OWNERSHIP_SENSITIVE_SUBCOMMANDS and (container_id or container_name):
                        unauthorized = check_unauthorized_access(db, container_id, container_name, parsed_res["user"])

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
                        unauthorized=unauthorized,
                    )
                    db.add(db_event)
                    db.commit()

                    if unauthorized:
                        print(f"[⚠️] YETKİSİZ ERİŞİM: {parsed_res['user']} -> {container_name}", flush=True)
                        print(f"[*] Event kaydedildi (audit_id={audit_id}), container={container_name}", flush=True)
                finally:
                    db.close()


@app.on_event("startup")
async def start_flush_task():
    asyncio.create_task(flush_loop())


@app.get("/")
def read_root():
    return {"status": "success", "message": "Docker Monitoring backend active\n"}


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


# ---------------- Loglar (Filtrelenebilir) ----------------

@app.get("/api/logs")
def get_logs_api(
    db: Session = Depends(get_db),
    user: str = None,
    container_name: str = None,
    status: str = None,
    start_date: str = None,
    end_date: str = None,
    command_contains: str = None,
    unauthorized_only: bool = False,
    limit: int = 100,
    _current_user: str = Depends(verify_token),   
):
    query = db.query(AuditEvent)
    if user:
        query = query.filter(AuditEvent.user == user)
    if container_name:
        query = query.filter(AuditEvent.container_name == container_name)
    if status:
        query = query.filter(AuditEvent.status == status)
    if start_date:
        query = query.filter(AuditEvent.timestamp >= start_date)
    if end_date:
        query = query.filter(AuditEvent.timestamp <= end_date)
    if command_contains:
        query = query.filter(AuditEvent.command.ilike(f"%{command_contains}%"))
    if unauthorized_only:
        query = query.filter(AuditEvent.unauthorized == True) 

    logs = query.order_by(AuditEvent.id.desc()).limit(limit).all()

    # Container owner bilgisini ekle
    container_ids = {log.container_id for log in logs if log.container_id}
    owners_by_id = {}
    if container_ids:
        infos = db.query(ContainerInfo).filter(ContainerInfo.container_id.in_(container_ids)).all()
        owners_by_id = {info.container_id: info.owner for info in infos}

    result = []
    for log in logs:
        result.append({
            "id": log.id,
            "timestamp": log.timestamp,
            "user": log.user,
            "status": log.status,
            "pid": log.pid,
            "executable": log.executable,
            "operation": log.operation,
            "syscall": log.syscall,
            "command": log.command,
            "container_id": log.container_id,
            "container_name": log.container_name,
            "container_owner": owners_by_id.get(log.container_id),
            "unauthorized": log.unauthorized,
        })

    return result

# ---------------- Metrikler ----------------

@app.post("/api/metrics/ingest")
def ingest_metrics(payload: dict, db: Session = Depends(get_db)):
    now = datetime.now()
    db.add(SystemMetrics(
        timestamp=now,
        target_type=payload.get("target_type", "unknown"),
        target_name=payload.get("target_name", "unknown"),
        cpu_usage=payload.get("cpu_usage", 0),
        ram_usage=payload.get("ram_usage", 0),
        ram_usage_mb=payload.get("ram_usage_mb", 0),
        ram_total_mb=payload.get("ram_total_mb", 0),
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
            SystemMetrics.ram_usage_mb,
            SystemMetrics.ram_total_mb,
            SystemMetrics.timestamp,
        )
        .order_by(SystemMetrics.timestamp.desc())
        .limit(300)
        .all()
    )

    latest = {}
    for row in subq:
        key = (row.target_type, row.target_name)
        if key not in latest:
            latest[key] = row

    hosts, containers = [], []
    for (t_type, t_name), row in latest.items():
        entry = {
            "name": t_name, "cpu": row.cpu_usage, "ram": row.ram_usage,
            "ram_mb": row.ram_usage_mb, "ram_total_mb": row.ram_total_mb,
            "status": "running",
        }
        (hosts if t_type == "host" else containers).append(entry)

    hosts.sort(key=lambda h: h["name"])
    containers.sort(key=lambda c: c["name"])
    return {"hosts": hosts, "containers": containers}


@app.get("/api/metrics/history")
def get_metrics_history(
    start_date: str = None,
    end_date: str = None,
    server_name: str = None,
    db: Session = Depends(get_db),
    _current_user: str = Depends(verify_token),
        
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
        {"timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S"), "cpu_usage": r.cpu_usage,
         "ram_usage": r.ram_usage, "ram_usage_mb": r.ram_usage_mb, "ram_total_mb": r.ram_total_mb, "name": r.target_name}
        for r in rows if r.target_type == "host"
    ]
    container_rows = [
        {"timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S"), "cpu_usage": r.cpu_usage,
         "ram_usage": r.ram_usage, "ram_usage_mb": r.ram_usage_mb, "ram_total_mb": r.ram_total_mb, "name": r.target_name}
        for r in rows if r.target_type == "container"
    ]
    return {"host": host_rows, "containers": container_rows}


# ---------------- Docker Events ----------------

@app.post("/api/docker-events/ingest")
def ingest_docker_event(payload: dict, db: Session = Depends(get_db)):
    event_time = float(payload.get("event_time", time.time()))
    container_id = payload.get("container_id", "")
    container_name = payload.get("container_name", "unknown")
    action = payload.get("action", "unknown")
    owner = payload.get("owner", "unknown")
    server_name = payload.get("server_name", "unknown")

    recent_docker_events.append({
        "container_id": container_id,
        "container_name": container_name,
        "action": action,
        "event_time": event_time,
    })

    db.add(ContainerEvent(
        server_name=server_name,
        container_id=container_id,
        container_name=container_name,
        action=action,
        owner=owner if owner != "unknown" else None,
        timestamp=datetime.fromtimestamp(event_time),
    ))
    db.commit()

    if owner and owner != "unknown" and container_id:
        info = db.query(ContainerInfo).filter(ContainerInfo.container_id == container_id).first()
        if info:
            info.owner = owner
            db.commit()

            
    # --- stop/die durumunda status güncelle, destroy/rm durumunda kaydı sil ---
    if container_id:
        info = db.query(ContainerInfo).filter(ContainerInfo.container_id == container_id).first()
        if info:
            if action in ("stop", "die", "kill"):
                info.status = "exited"
                info.last_seen = datetime.now()
                db.commit()
                print(f"[*] Container durduruldu: {container_name} ({action})", flush=True)
            elif action == "destroy":
                db.delete(info)
                db.commit()
                print(f"[*] Container silindi: {container_name}", flush=True)
            
    return {"status": "ok"}


# ---------------- containerlar ----------------

@app.post("/api/containers/ingest")
def ingest_container_info(payload: dict, db: Session = Depends(get_db)):
    container_id = payload.get("container_id", "")
    if not container_id:
        return {"status": "ignored"}

    info = db.query(ContainerInfo).filter(ContainerInfo.container_id == container_id).first()
    if info is None:
        info = ContainerInfo(container_id=container_id)
        db.add(info)

    info.container_name = payload.get("container_name", "unknown")
    info.status = payload.get("status", "unknown")
    info.server_name = payload.get("server_name", "unknown")
    info.image = payload.get("image", "")

    owner = payload.get("owner", "unknown")
    if owner and owner != "unknown":
        info.owner = owner
    elif info.owner is None:
        info.owner = "unknown"

    info.last_seen = datetime.now()
    db.commit()
    return {"status": "ok"}


@app.get("/api/containers")
def get_containers(
    server_name: str = None,
    status: str = None,
    owner: str = None,
    db: Session = Depends(get_db),
    _current_user: str = Depends(verify_token),
):
    query = db.query(ContainerInfo)
    if server_name:
        query = query.filter(ContainerInfo.server_name == server_name)
    if status:
        query = query.filter(ContainerInfo.status == status)
    if owner:
        query = query.filter(ContainerInfo.owner == owner)
    return query.order_by(ContainerInfo.container_name.asc()).all()


@app.get("/api/containers/summary")
def get_containers_summary(db: Session = Depends(get_db)):
    containers = db.query(ContainerInfo).all()
    running = sum(1 for c in containers if c.status == "running")
    stopped = sum(1 for c in containers if c.status != "running")
    return {"running": running, "stopped": stopped, "total": len(containers)}


@app.get("/api/containers/{container_id}/timeline")
def get_container_timeline(container_id: str, db: Session = Depends(get_db)):
    events = (
        db.query(ContainerEvent)
        .filter(ContainerEvent.container_id == container_id)
        .order_by(ContainerEvent.timestamp.asc())
        .all()
    )
    logs = (
        db.query(AuditEvent)
        .filter(AuditEvent.container_id == container_id)
        .order_by(AuditEvent.id.asc())
        .all()
    )

    timeline = []
    for e in events:
        timeline.append({
            "type": "docker_event",
            "timestamp": e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "action": e.action,
            "detail": f"Docker olayı: {e.action}",
        })
    for l in logs:
        timeline.append({
            "type": "audit_log",
            "timestamp": l.timestamp,
            "action": l.command,
            "user": l.user,
            "unauthorized": l.unauthorized,
            "detail": l.command,
        })

    timeline.sort(key=lambda x: x["timestamp"])
    return timeline
