import json
import time
from typing import Optional, Dict, Any
from redis import Redis
from app.core.config import settings
from app.core.logging import logger
from app.db.session import SessionLocal
from app.storage.local import LocalEvidenceStorage
from app.services.email_analysis.orchestrator import AnalysisOrchestrator

def get_redis_client() -> Optional[Redis]:
    try:
        r = Redis.from_url(settings.REDIS_URL, decode_responses=True, socket_connect_timeout=2)
        r.ping()
        return r
    except Exception as e:
        logger.warning(f"Redis connection failed ({settings.REDIS_URL}): {e}. Async queue unavailable.")
        return None

def enqueue_analysis_job(analysis_id: str, filename: str) -> bool:
    """Push analysis task onto Redis background worker queue."""
    r = get_redis_client()
    if not r:
        return False
    try:
        payload = json.dumps({
            "analysis_id": analysis_id,
            "filename": filename,
            "enqueued_at": time.time(),
        })
        r.lpush(settings.REDIS_QUEUE_NAME, payload)
        logger.info(f"Enqueued background job for {analysis_id}", extra={"analysis_id": analysis_id, "status": "queued"})
        return True
    except Exception as e:
        logger.error(f"Failed to enqueue Redis job: {e}")
        return False

def run_worker_loop():
    """Standalone background worker process polling Redis queue."""
    logger.info(f"Starting AEGIS Email Analysis Worker on queue '{settings.REDIS_QUEUE_NAME}'...")
    r = get_redis_client()
    if not r:
        logger.error("Worker cannot start: Redis broker is unreachable.")
        return

    storage = LocalEvidenceStorage()

    while True:
        try:
            # Blocking pop with 5s timeout
            item = r.brpop(settings.REDIS_QUEUE_NAME, timeout=5)
            if not item:
                continue

            _, raw_payload = item
            job_data = json.loads(raw_payload)
            analysis_id = job_data["analysis_id"]
            filename = job_data.get("filename", "untrusted_input.eml")

            logger.info(f"Worker picked up job {analysis_id}", extra={"analysis_id": analysis_id, "stage": "worker_received"})

            # Load evidence bytes
            raw_bytes = storage.get_evidence(analysis_id)
            if not raw_bytes:
                logger.error(f"Evidence file missing for {analysis_id}")
                continue

            # Execute orchestrator pipeline
            db = SessionLocal()
            try:
                orchestrator = AnalysisOrchestrator(db, storage)
                orchestrator.process_email(
                    raw_bytes=raw_bytes,
                    filename=filename,
                    analysis_id=analysis_id,
                    force_reanalysis=True,
                )
                logger.info(f"Worker completed job {analysis_id}", extra={"analysis_id": analysis_id, "status": "completed"})
            finally:
                db.close()

        except KeyboardInterrupt:
            logger.info("Worker stopped by user signal.")
            break
        except Exception as e:
            logger.error(f"Worker loop error: {e}")
            time.sleep(1)

if __name__ == "__main__":
    run_worker_loop()
