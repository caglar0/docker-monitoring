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
from threading import Lock


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
JWT_EXPIRE_HOURS = 168


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
DOCKER_EVENT_MATCH_WINDOW = 1.5

REQUIRES_CONTAINER_EVENT_MATCH = {
    "exec", "start", "stop", "restart", "kill", "rm", "logs", "attach", "cp", "pause", "unpause", "run", "create",
}

NOISE_SUBCOMMANDS = {
    "info", "version", "ps", "events", "logs",
}

# Yetkisiz erişim kontrolü uygulanacak subcommandler
OWNERSHIP_SENSITIVE_SUBCOMMANDS = {
    "exec", "start", "stop", "restart", "kill", "rm", "logs", "attach", "cp", "pause", "unpause",
}

# subcommandlerde container zaten var, evente gerek yok - direkt argümandan alınır
DIRECT_TARGET_SUBCOMMANDS = {
    "start", "stop", "restart", "kill", "rm", "exec",
    "logs", "attach", "cp", "pause", "unpause",
}

# container henüz yok, event correlation gerekli
EVENT_CORRELATION_SUBCOMMANDS = {"run", "create"}


container_action_queue: deque = deque()  # {"audit_id", "epoch"} - isimsiz run/create bekleyenler
container_queue_lock = Lock()
resolved_container_matches: dict[str, dict] = {}  # audit_id -> {container_id, container_name}
MAX_WAIT_FOR_EVENT = 5.0

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

def extract_positional_target(command: str, subcommand: str) -> str | None:
    """
    start/stop/exec/kill/rm/pause/unpause/logs/attach/cp gibi komutlarda
    container adı komutun kendi argümanında zaten var - onu çıkarır.
    Flag'leri (- ile başlayanları) atlar, ilk pozisyonel argümanı döner.
    """
    parts = command.strip().split()
    if len(parts) < 3:
        return None
    # parts[0]="docker", parts[1]=subcommand, parts[2:]=argümanlar
    for token in parts[2:]:
        if not token.startswith("-"):
            return token
    return None

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
    # Pencere içindeki tüm adayları bul
    candidates = [
        e for e in recent_docker_events
        if abs(e["event_time"] - audit_epoch) <= DOCKER_EVENT_MATCH_WINDOW
    ]
    if not candidates:
        return None
    # En yakın olanı seç
    return min(candidates, key=lambda e: abs(e["event_time"] - audit_epoch))

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
                command_parts = (parsed_res["command"] or "").strip().split()
                subcommand = command_parts[1].lower() if len(command_parts) > 1 else ""

                container_id = None
                container_name = None
                match_found = False

                if subcommand in DIRECT_TARGET_SUBCOMMANDS:
                    # 1: Container adı/ID zaten komutun argümanında var
                    target = extract_positional_target(parsed_res["command"], subcommand)
                    if target:
                        #info = (
                            #db_lookup_container_by_name_or_id(target)
                            #if False else None
                        #)
                        
                        db_temp = SessionLocal()
                        try:
                            info = (
                                db_temp.query(ContainerInfo)
                                .filter(
                                    (ContainerInfo.container_name == target) |
                                    (ContainerInfo.container_id.like(f"{target}%"))
                                )
                                .first()
                            )
                            if info:
                                container_id = info.container_id
                                container_name = info.container_name
                                match_found = True
                        finally:
                            db_temp.close()

                elif subcommand in EVENT_CORRELATION_SUBCOMMANDS:
                    intended_name = extract_intended_container_name(parsed_res["command"] or "")
                    if intended_name:
                        # 2: --name verilmiş, isim bazlı kesin eşleştirme
                        name_matches = [
                            e for e in recent_docker_events
                            if e["container_name"] == intended_name and e["action"] in ("create", "start")
                            and abs(e["event_time"] - parsed_res["_epoch"]) <= DOCKER_EVENT_MATCH_WINDOW
                        ]
                        if name_matches:
                            best = min(name_matches, key=lambda e: abs(e["event_time"] - parsed_res["_epoch"]))
                            container_id = best["container_id"]
                            container_name = best["container_name"]
                            match_found = True
                    else:
                        # 3: İsimsiz, FIFO kuyruktan çözülmüş mü kontrol et
                        resolved = resolved_container_matches.pop(audit_id, None)
                        if resolved:
                            container_id = resolved["container_id"]
                            container_name = resolved["container_name"]
                            match_found = True

                if subcommand in REQUIRES_CONTAINER_EVENT_MATCH and not match_found:
                    parsed_res["status"] = "FAILED"
                    print(f"[!] Eşleşme bulunamadı, FAILED: {parsed_res['command']}", flush=True)

                db = SessionLocal()
                try:
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
                    print(f"[*] Kaydedildi (audit_id={audit_id}), container={container_name}, status={parsed_res['status']}", flush=True)
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

    # EXECVE satırı geldiyse isimsiz run/create ise FIFO kuyruğa erken kaydet
    if "type=EXECVE" in raw_log:
        command = extract_execve(raw_log)
        parts = command.strip().split()
        if len(parts) >= 2:
            subcommand = parts[1].lower()
            if subcommand in EVENT_CORRELATION_SUBCOMMANDS:
                intended_name = extract_intended_container_name(command)
                if not intended_name:  # --name yoksa, FIFO'ya kaydet
                    ts_match = AUDIT_TIMESTAMP_PATTERN.search(raw_log)
                    epoch = float(ts_match.group(1)) if ts_match else time.time()
                    with container_queue_lock:
                        container_action_queue.append({"audit_id": audit_id, "epoch": epoch})

    return Response(content="Log buffer'a eklendi\n", media_type="text/plain")

NAME_FLAG_PATTERN = re.compile(r'--name[=\s]+([a-zA-Z0-9_.-]+)')

def extract_intended_container_name(command: str) -> str | None:
    match = NAME_FLAG_PATTERN.search(command)
    return match.group(1) if match else None

# ---------------- Loglar ----------------

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
        query = query.filter(AuditEvent.command.op("~*")(rf"\y{re.escape(command_contains)}\y"))
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
def get_live_metrics(db: Session = Depends(get_db), _current_user: str = Depends(verify_token)):
    subq = (
        db.query(
            SystemMetrics.target_name, SystemMetrics.target_type, SystemMetrics.cpu_usage,
            SystemMetrics.ram_usage, SystemMetrics.ram_usage_mb, SystemMetrics.ram_total_mb,
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

    # Sadece u an çalışan containerların isim setini oluştur
    infos = db.query(ContainerInfo).filter(ContainerInfo.status == "running").all()
    existing_names = set()
    for info in infos:
        existing_names.add(f"{info.server_name}/{info.container_name}")
        existing_names.add(info.container_name)

    hosts, containers = [], []
    for (t_type, t_name), row in latest.items():
        if t_type == "container" and t_name not in existing_names:
            continue
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

    # Her container için: qualified isim -> deleted_at (silinmemişse None)
    infos = db.query(ContainerInfo).all()
    deleted_at_by_name = {}
    for info in infos:
        deleted_at_by_name[f"{info.server_name}/{info.container_name}"] = info.deleted_at
        deleted_at_by_name[info.container_name] = info.deleted_at

    def is_valid_at(target_name: str, ts) -> bool:
        # Container hiç kayıtlı değilse (agent hiç görmediyse), veriyi göster
        if target_name not in deleted_at_by_name:
            return True
        deleted_at = deleted_at_by_name[target_name]
        if deleted_at is None:
            return True  # hala yaşıyor, her zaman geçerli
        return ts <= deleted_at  # sadece silinmeden önceki veriler geçerli

    host_rows = [
        {"timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S"), "cpu_usage": r.cpu_usage,
         "ram_usage": r.ram_usage, "ram_usage_mb": r.ram_usage_mb, "ram_total_mb": r.ram_total_mb, "name": r.target_name}
        for r in rows if r.target_type == "host"
    ]
    container_rows = [
        {"timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S"), "cpu_usage": r.cpu_usage,
         "ram_usage": r.ram_usage, "ram_usage_mb": r.ram_usage_mb, "ram_total_mb": r.ram_total_mb, "name": r.target_name}
        for r in rows if r.target_type == "container" and is_valid_at(r.target_name, r.timestamp)
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

    event_entry = {
        "container_id": container_id,
        "container_name": container_name,
        "action": action,
        "event_time": event_time,
    }

    # Sadece create/start eventleri 
    if action in ("create", "start"):
        with container_queue_lock:
            now = time.time()
            # Süresi dolmuş istekleri temizle
            while container_action_queue and (now - container_action_queue[0]["epoch"] > MAX_WAIT_FOR_EVENT):
                container_action_queue.popleft()

            if container_action_queue:
                req = container_action_queue.popleft()
                resolved_container_matches[req["audit_id"]] = {
                    "container_id": container_id,
                    "container_name": container_name,
                }

    # İsim bazlı eşleştirme için (run --name  durumları) eski deque'ye de ekle
    recent_docker_events.append(event_entry)

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

    if container_id:
        info = db.query(ContainerInfo).filter(ContainerInfo.container_id == container_id).first()
        if info:
            if action in ("stop", "die", "kill"):
                info.status = "exited"
                info.last_seen = datetime.now()
                db.commit()
            elif action == "destroy":
                info.status = "deleted"
                info.deleted_at = datetime.fromtimestamp(event_time)
                db.commit()
                print(f"[*] Container silindi olarak işaretlendi: {container_name}", flush=True)

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
        include_deleted: bool = False,
        db: Session = Depends(get_db),
        _current_user: str = Depends(verify_token),
):
    query = db.query(ContainerInfo)
    if not include_deleted:
        query = query.filter(ContainerInfo.status != "deleted")
    if server_name:
        query = query.filter(ContainerInfo.server_name == server_name)
    if status:
        query = query.filter(ContainerInfo.status == status)
    if owner:
        query = query.filter(ContainerInfo.owner == owner)
    return query.order_by(ContainerInfo.container_name.asc()).all()

@app.get("/api/containers/summary")
def get_containers_summary(db: Session = Depends(get_db)):
    containers = db.query(ContainerInfo).filter(ContainerInfo.status != "deleted").all()
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

@app.get("/api/users/resource-usage")
def get_user_resource_usage(db: Session = Depends(get_db), _current_user: str = Depends(verify_token)):
    subq = (
        db.query(
            SystemMetrics.target_name, SystemMetrics.cpu_usage, SystemMetrics.ram_usage,
            SystemMetrics.ram_usage_mb, SystemMetrics.ram_total_mb, SystemMetrics.timestamp,
        )
        .filter(SystemMetrics.target_type == "container")
        .order_by(SystemMetrics.timestamp.desc())
        .limit(300)
        .all()
    )

    latest_by_container = {}
    for row in subq:
        if row.target_name not in latest_by_container:
            latest_by_container[row.target_name] = row

    # Sadece silinmemiş containerlar
    infos = db.query(ContainerInfo).filter(ContainerInfo.status == "running").all()
    owner_by_qualified_name = {}
    existing_qualified_names = set()
    for info in infos:
        for key in (f"{info.server_name}/{info.container_name}", info.container_name):
            owner_by_qualified_name[key] = info.owner or "unknown"
            existing_qualified_names.add(key)

    usage_by_owner = {}
    for target_name, row in latest_by_container.items():
        if target_name not in existing_qualified_names:
            continue
        owner = owner_by_qualified_name.get(target_name, "unknown")
        if owner == "unknown":
            continue
        if owner not in usage_by_owner:
            usage_by_owner[owner] = {"owner": owner, "cpu_total": 0.0, "ram_total_mb": 0.0, "ram_capacity_mb": 0.0, "containers": []}
        ram_mb = row.ram_usage_mb or 0
        ram_capacity = row.ram_total_mb or 0
        usage_by_owner[owner]["cpu_total"] += row.cpu_usage or 0
        usage_by_owner[owner]["ram_total_mb"] += ram_mb
        usage_by_owner[owner]["ram_capacity_mb"] += ram_capacity
        usage_by_owner[owner]["containers"].append({
            "name": target_name.split("/")[-1], "cpu": round(row.cpu_usage or 0, 2),
            "ram_mb": round(ram_mb, 2),
            "ram_percent": round(100 * ram_mb / ram_capacity, 1) if ram_capacity > 0 else 0,
        })

    result = sorted(usage_by_owner.values(), key=lambda x: x["cpu_total"], reverse=True)
    for r in result:
        r["cpu_total"] = round(r["cpu_total"], 2)
        r["ram_total_mb"] = round(r["ram_total_mb"], 2)
        r["ram_percent"] = round(100 * r["ram_total_mb"] / r["ram_capacity_mb"], 1) if r["ram_capacity_mb"] > 0 else 0
        r["container_count"] = len(r["containers"])
    return result


@app.get("/api/users/resource-usage/history")
def get_user_resource_history(
    start_date: str = None,
    end_date: str = None,
    db: Session = Depends(get_db),
    _current_user: str = Depends(verify_token),
):
    query = db.query(SystemMetrics).filter(SystemMetrics.target_type == "container")
    if start_date:
        query = query.filter(SystemMetrics.timestamp >= start_date)
    if end_date:
        query = query.filter(SystemMetrics.timestamp <= end_date)

    rows = query.order_by(SystemMetrics.timestamp.asc()).limit(5000).all()

    infos = db.query(ContainerInfo).all()
    owner_by_name = {}
    deleted_at_by_name = {}
    for info in infos:
        for key in (f"{info.server_name}/{info.container_name}", info.container_name):
            owner_by_name[key] = info.owner or "unknown"
            deleted_at_by_name[key] = info.deleted_at

    def is_valid_at(target_name: str, ts) -> bool:
        if target_name not in deleted_at_by_name:
            return True
        deleted_at = deleted_at_by_name[target_name]
        return deleted_at is None or ts <= deleted_at

    buckets = {}
    for row in rows:
        if not is_valid_at(row.target_name, row.timestamp):
            continue

        owner = owner_by_name.get(row.target_name, "unknown")
        if owner == "unknown":
            continue

        bucket_time = row.timestamp.replace(second=0, microsecond=0)
        key = (owner, bucket_time)

        if key not in buckets:
            buckets[key] = {"owner": owner, "timestamp": bucket_time, "cpu_total": 0.0, "ram_total_mb": 0.0, "ram_capacity_mb": 0.0}

        buckets[key]["cpu_total"] += row.cpu_usage or 0
        buckets[key]["ram_total_mb"] += row.ram_usage_mb or 0
        buckets[key]["ram_capacity_mb"] += row.ram_total_mb or 0

    result = []
    for (owner, ts), data in sorted(buckets.items(), key=lambda x: x[0][1]):
        ram_percent = round(100 * data["ram_total_mb"] / data["ram_capacity_mb"], 1) if data["ram_capacity_mb"] > 0 else 0
        result.append({
            "owner": owner, "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "cpu_total": round(data["cpu_total"], 2), "ram_total_mb": round(data["ram_total_mb"], 2), "ram_percent": ram_percent,
        })
    return result
