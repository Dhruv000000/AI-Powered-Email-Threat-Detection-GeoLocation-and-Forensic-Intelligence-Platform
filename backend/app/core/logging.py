import logging
import sys
import json
from typing import Any, Dict, Optional

class StructuredFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        # Capture forensic context fields if attached
        for attr in ("analysis_id", "stage", "status", "duration_ms", "sha256", "error_code"):
            if hasattr(record, attr):
                log_entry[attr] = getattr(record, attr)
                
        return json.dumps(log_entry)

def setup_logging(level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("aegis")
    logger.setLevel(level)
    logger.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    handler.setFormatter(StructuredFormatter())
    logger.addHandler(handler)
    logger.propagate = False
    return logger

logger = setup_logging()

def get_forensic_logger(analysis_id: Optional[str] = None):
    return logging.LoggerAdapter(logger, {"analysis_id": analysis_id or "system"})
