import json
import time
from typing import Optional
from redis import Redis
from app.core.config import settings
from app.core.logging import logger
from app.db.session import SessionLocal
from app.services.investigation.orchestrator import InvestigationOrchestrator


def get_redis_client() -> Optional[Redis]:
    try:
        r = Redis.from_url(settings.REDIS_URL, decode_responses=True, socket_connect_timeout=2)
        r.ping()
        return r
    except Exception as e:
        logger.warning(f"Redis connection failed ({settings.REDIS_URL}): {e}. Investigation async queue unavailable.")
        return None


def enqueue_investigation_job(
    analysis_id: str,
    investigation_id: str,
    force_reinvestigation: bool = False,
) -> bool:
    """Push investigation task onto Redis background worker queue."""
    r = get_redis_client()
    if not r:
        return False
    try:
        payload = json.dumps({
            "analysis_id": analysis_id,
            "investigation_id": investigation_id,
            "force_reinvestigation": force_reinvestigation,
            "enqueued_at": time.time(),
        })
        r.lpush(settings.REDIS_INVESTIGATION_QUEUE_NAME, payload)
        logger.info(
            f"Enqueued investigation background job for {investigation_id} (Analysis: {analysis_id})",
            extra={"investigation_id": investigation_id, "status": "queued"}
        )
        return True
    except Exception as e:
        logger.error(f"Failed to enqueue investigation Redis job: {e}")
        return False


def run_investigation_worker_loop():
    """Standalone background worker process polling Redis investigation queue."""
    logger.info(f"Starting AEGIS Investigation Worker on queue '{settings.REDIS_INVESTIGATION_QUEUE_NAME}'...")
    r = get_redis_client()
    if not r:
        logger.error("Investigation Worker cannot start: Redis broker is unreachable.")
        return

    while True:
        try:
            # Blocking pop with 5s timeout
            item = r.brpop(settings.REDIS_INVESTIGATION_QUEUE_NAME, timeout=5)
            if not item:
                continue

            _, raw_payload = item
            job_data = json.loads(raw_payload)
            analysis_id = job_data["analysis_id"]
            investigation_id = job_data.get("investigation_id", "INV-UNKNOWN")
            force_reinvestigation = job_data.get("force_reinvestigation", False)

            logger.info(
                f"Worker picked up investigation job {investigation_id}",
                extra={"investigation_id": investigation_id, "analysis_id": analysis_id, "stage": "worker_received"}
            )

            # Execute orchestrator pipeline
            db = SessionLocal()
            try:
                orchestrator = InvestigationOrchestrator(db)
                orchestrator.run_investigation(
                    analysis_id=analysis_id,
                    force_reinvestigation=force_reinvestigation,
                )
                logger.info(
                    f"Worker completed investigation job {investigation_id}",
                    extra={"investigation_id": investigation_id, "status": "completed"}
                )
            except Exception as job_err:
                logger.error(f"Worker failed processing investigation {investigation_id}: {job_err}")
            finally:
                db.close()

        except KeyboardInterrupt:
            logger.info("Investigation Worker stopped by user signal.")
            break
        except Exception as e:
            logger.error(f"Investigation Worker loop error: {e}")
            time.sleep(1)


if __name__ == "__main__":
    run_investigation_worker_loop()
