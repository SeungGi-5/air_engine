# core/dispatcher.py

# from playbooks import default_reactive_response
import logging
import asyncio
from typing import Dict, Any, List, Tuple, Callable
from playbooks import reactive_ip_check, complex_webshell_response

logger = logging.getLogger("Dispatcher")

class PlaybookDispatcher:
    def __init__(self):
        # # Wazuh Rule ID와 실제 실행할 함수를 1:1로 매핑합니다.
        # self.rule_map = {
        #     # [Case 1] SSH 로그인 실패 (Rule ID: 5710, 5711 등) -> IP 차단 로직 실행
        #     "5710": default_reactive_response.handle_ip_block, 
        #     "5711": default_reactive_response.handle_ip_block,
        #     "5712": default_reactive_response.handle_ip_block,

        #     # [Case 2] Struts RCE 공격 탐지 (Custom Rule ID: 100500) -> 가상 패치 실행
        #     "100500": default_reactive_response.handle_struts_rce
        # }

        # 형식: (시작ID, 종료ID, 실행할_함수)
        # 예: 100000 ~ 199999 대역은 모두 reactive_ip_check 실행 (네트워크/웹 공격)
        self.ROUTE_MAP: List[Tuple[int, int, Callable]] = [
            (100000, 199999, reactive_ip_check.run),
            (200000, 200200, complex_webshell_response.run), # 예: 악성코드/EDR 관련
        ]
        
    async def dispatch(self, alert_data: Dict[str, Any]):
        """
        Alert 데이터를 받아 룰 ID에 매칭되는 플레이북을 비동기로 실행
        """
        try:
            # Rule ID 추출
            rule_info = alert_data.get('rule', {})
            rule_id_str = rule_info.get('id')
            
            if not rule_id_str:
                logger.warning("Alert received without Rule ID. Skipping.")
                return

            try:
                rule_id = int(rule_id_str)
            except ValueError:
                logger.error(f"Invalid Rule ID format: {rule_id_str}")
                return

            description = rule_info.get('description', 'Unknown Alert')
            logger.info(f"Analyzing Alert: [{rule_id}] {description}")

            # 라우팅 로직 수행
            matched_handler = None
            
            for start_id, end_id, handler in self.ROUTE_MAP:
                if start_id <= rule_id <= end_id:
                    matched_handler = handler
                    break
            
            # 매칭된 핸들러 실행
            if matched_handler:
                logger.info(f"Routing Rule ID {rule_id} to Playbook: {matched_handler.__module__}")
                # 플레이북 실행 (await로 실행하여 완료 대기)
                await matched_handler(alert_data)
            else:
                logger.info(f"No playbook matched for Rule ID {rule_id}. Logging only.")

        except Exception as e:
            logger.error(f"Dispatcher Error: {e}", exc_info=True)