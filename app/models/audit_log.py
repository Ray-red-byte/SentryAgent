from sqlalchemy import Column, String, Integer, ForeignKey, JSON, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base

class AuditSession(Base):
    __tablename__ = "sessions"

    id = Column(String, primary_key=True, index=True) # UUID
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationship to logs
    logs = relationship("AuditLog", back_populates="session")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, ForeignKey("sessions.id"))
    file_path = Column(String)
    
    # We store the entire JSON report from the LLM here
    vuln_report = Column(JSON) 
    
    session = relationship("AuditSession", back_populates="logs")