# main.py

import uvicorn
from core.dispatcher import PlaybookDispatcher # core.dispatcher에서 import
import os
# from config import WAZUH_PASS # config.py에서 패스워드 로드 
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, BackgroundTasks, HTTPException

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("AIR_Engine_Main")

# -------------------------------------------------------------------------
# 생명주기 관리 (Lifespan)
# 애플리케이션 시작 시 Dispatcher를 초기화하고 종료 시 리소스를 정리
# -------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # [시작] Dispatcher 인스턴스 생성 및 로드
    logger.info("Initializing A.I.R. Engine Dispatcher...")
    app.state.dispatcher = PlaybookDispatcher()
    logger.info("Dispatcher is ready to handle alerts.")
    yield
    # [종료] 필요 시 커넥터 세션 종료 등 정리 작업
    logger.info("Shutting down A.I.R. Engine...")

# -------------------------------------------------------------------------
# FastAPI 앱 초기화
# -------------------------------------------------------------------------
app = FastAPI(
    title="A.I.R. Platform Engine",
    description="Automated & Intelligent Response Engine for Wazuh SOAR",
    version="1.0.0",
    lifespan=lifespan
)
# dispatcher = PlaybookDispatcher() 

# @app.get("/")
# def health_check():
#     return {"status": "Online", "role": "A.I.R. Orchestration Center"}

# @app.post("/api/v1/alert")
# async def receive_wazuh_alert(request: Request):
#     try:
#         raw_data = await request.json()
#         rule_id = raw_data.get('rule', {}).get('id')
        
#         action = dispatcher.run_playbook_by_rule(rule_id, raw_data)
        
#         return {"status": "processed", "action_taken": action}
        
#     except Exception as e:
#         print(f"[ERROR] Alert processing failed: {e}")
#         return {"status": "error", "message": str(e)}


# -------------------------------------------------------------------------
# API 엔드포인트 정의
# -------------------------------------------------------------------------
@app.post("/api/v1/webhook")
async def wazuh_alert_webhook(request: Request, background_tasks: BackgroundTasks):
    """
    [핵심] Wazuh Integration으로부터 Alert JSON을 수신하는 Webhook
    
    동작 방식:
    1. 요청(Alert Data)을 수신.
    2. Wazuh에게 즉시 200 OK 응답 (Wazuh 측 Timeout 방지).
    3. 실제 분석 및 차단 로직(Playbook)은 백그라운드에서 비동기로 실행.
    """
    try:
        # 1. JSON 데이터 파싱
        alert_data = await request.json()
        
        # 2. 데이터 유효성 검사 (최소한의 확인)
        if not alert_data or 'rule' not in alert_data:
            logger.warning("Received invalid alert format (missing 'rule' key).")
            raise HTTPException(status_code=400, detail="Invalid alert format")

        rule_id = alert_data.get('rule', {}).get('id', 'Unknown')
        logger.info(f"[-] Received Alert: Rule ID {rule_id}")

        # 3. Dispatcher 호출 (백그라운드 작업 등록)
        # app.state.dispatcher를 통해 싱글톤 인스턴스 사용
        dispatcher: PlaybookDispatcher = app.state.dispatcher
        background_tasks.add_task(dispatcher.dispatch, alert_data)

        # 4. 즉시 응답
        return {
            "status": "received", 
            "msg": f"Alert {rule_id} queued for processing"
        }

    except Exception as e:
        logger.error(f"Error processing webhook request: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal Server Error")


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
