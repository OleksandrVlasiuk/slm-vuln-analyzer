from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey, DateTime, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import datetime

SQLALCHEMY_DATABASE_URL = "sqlite:///./slm_scanner.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)  # PBKDF2-HMAC-SHA256 хеш (hex); порожній salt => legacy plaintext
    salt = Column(String)  # hex, унікальна для кожного користувача
    role = Column(String, default="developer") # developer або admin

    sessions = relationship("ScanSession", back_populates="owner")

class ScanSession(Base):
    __tablename__ = "scan_sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True) # Зв'язок з користувачем
    scan_type = Column(String, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    owner = relationship("User", back_populates="sessions")
    vulnerabilities = relationship("Vulnerability", back_populates="session")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("scan_sessions.id"))
    file_path = Column(String, index=True)
    rule_id = Column(String, index=True)
    code_snippet = Column(String)

    session = relationship("ScanSession", back_populates="vulnerabilities")
    ai_explanation = relationship("AIExplanation", back_populates="vulnerability", uselist=False)

class AIExplanation(Base):
    __tablename__ = "ai_explanations"

    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"))
    model_name = Column(String, index=True)
    explanation_text = Column(String)
    inference_time = Column(Float)

    # Метрики генерації (заповнюються при кожному виклику ollama_client)
    prompt_version = Column(String)
    device = Column(String)
    temperature = Column(Float)
    top_p = Column(Float)
    load_duration_s = Column(Float)
    prompt_tokens = Column(Integer)
    prompt_eval_s = Column(Float)
    output_tokens = Column(Integer)
    eval_s = Column(Float)
    tokens_per_sec = Column(Float)
    total_s = Column(Float)
    gpu_share = Column(Float)
    done_reason = Column(String)

    vulnerability = relationship("Vulnerability", back_populates="ai_explanation")


# Нові колонки AIExplanation. Для нової БД create_all() вже створює їх усі;
# для існуючої БД без цих колонок вони додаються нижче через ALTER TABLE без втрати даних.
_NEW_AI_EXPLANATION_COLUMNS = {
    "prompt_version": "VARCHAR",
    "device": "VARCHAR",
    "temperature": "FLOAT",
    "top_p": "FLOAT",
    "load_duration_s": "FLOAT",
    "prompt_tokens": "INTEGER",
    "prompt_eval_s": "FLOAT",
    "output_tokens": "INTEGER",
    "eval_s": "FLOAT",
    "tokens_per_sec": "FLOAT",
    "total_s": "FLOAT",
    "gpu_share": "FLOAT",
    "done_reason": "VARCHAR",
}


def _migrate_ai_explanations(engine):
    with engine.connect() as conn:
        existing = {row[1] for row in conn.execute(text("PRAGMA table_info(ai_explanations)"))}
        for col_name, col_type in _NEW_AI_EXPLANATION_COLUMNS.items():
            if col_name not in existing:
                conn.execute(text(f"ALTER TABLE ai_explanations ADD COLUMN {col_name} {col_type}"))
        conn.commit()


def _migrate_users(engine):
    with engine.connect() as conn:
        existing = {row[1] for row in conn.execute(text("PRAGMA table_info(users)"))}
        if "salt" not in existing:
            conn.execute(text("ALTER TABLE users ADD COLUMN salt VARCHAR"))
        conn.commit()


Base.metadata.create_all(bind=engine)
_migrate_ai_explanations(engine)
_migrate_users(engine)