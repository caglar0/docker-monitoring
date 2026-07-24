import os
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql://audit_user:audit_pass123@db:5432/audit_log_db"
)
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String, index=True)
    user = Column(String, nullable=True)
    status = Column(String, index=True)
    pid = Column(Integer, nullable=True)
    executable = Column(String, index=True)
    operation = Column(String)
    syscall = Column(String)
    command = Column(String, nullable=True)
    container_name = Column(String(255), nullable=True)  # şimdilik boş kalacak
    container_id = Column(String(64), nullable=True)
    unauthorized = Column(Boolean, default=False, index=True)
    
class SystemMetrics(Base):
    __tablename__ = "system_metrics"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, index=True)
    target_type = Column(String(50))    # "host" veya "container"
    target_name = Column(String(255))   # "host" veya container adı
    cpu_usage = Column(Float)
    ram_usage = Column(Float)
    ram_usage_mb = Column(Float, nullable=True)
    ram_total_mb = Column(Float, nullable=True)

class ContainerInfo(Base):
    """Her container'ın güncel durumu - agent periyodik olarak upsert eder."""
    __tablename__ = "container_info"
    id = Column(Integer, primary_key=True, index=True)
    container_id = Column(String(64), unique=True, index=True)
    container_name = Column(String(255), index=True)
    owner = Column(String(255), nullable=True, index=True)
    status = Column(String(50))  # "running" / "exited" / "deleted" vb.
    server_name = Column(String(255))
    image = Column(String(255), nullable=True)
    last_seen = Column(DateTime)
    deleted_at = Column(DateTime, nullable=True)  

class ContainerEvent(Base):
    """docker events akışının kalıcı hali - yaşam döngüsü zaman çizelgesi için."""
    __tablename__ = "container_events"
    id = Column(Integer, primary_key=True, index=True)
    server_name = Column(String(255))
    container_id = Column(String(64), index=True)
    container_name = Column(String(255), index=True)
    action = Column(String(50))
    owner = Column(String(255), nullable=True)
    timestamp = Column(DateTime, index=True)

    
Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
