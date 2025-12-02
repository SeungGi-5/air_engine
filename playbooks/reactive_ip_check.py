import logging
import asyncio
from typing import Dict, Any
from connectors.misp_connector import MispConnector
from connectors.pfsense_connector import PfSenseConnector

logger = logging.getLogger("Playbook:ReactiveIPCheck")

async def run(alert_data: Dict[str, Any]):
    """
    [시나리오] 악성 IP 탐지 및 차단 플레이북
    
    Logic:
    1. Alert에서 Source IP 추출
    2. MISP 평판 조회
    3. pfSense 차단 (Known -> 영구 차단 / Unknown -> 임시 차단)
    """
    try:
        # 1. 데이터 파싱 (Wazuh Alert Format)
        data = alert_data.get('data', {})
        src_ip = data.get('srcip')
        rule_desc = alert_data.get('rule', {}).get('description', 'No description')

        if not src_ip:
            logger.warning("No Source IP found in alert data. Playbook skipped.")
            return

        logger.info(f"Starting playbook for IP: {src_ip} (Trigger: {rule_desc})")

        # 2. 커넥터 인스턴스 생성
        misp = MispConnector()
        pfsense = PfSenseConnector()

        # 3. 위협 인텔리전스 조회 (Analyze & Decide) [cite: 76]
        # "정보 강화: MISP를 통해... 컨텍스트를 추가"
        is_known_malicious = await misp.check_ip_reputation(src_ip)

        # 4. 대응 수행 (Response) [cite: 81, 153]
        if is_known_malicious:
            # Case A: MISP에 등록된 확실한 악성 IP -> 영구 차단
            logger.info(f"[DECISION] IP {src_ip} is CONFIRMED MALICIOUS. Applying Permanent Block.")
            success = await pfsense.block_ip(ip=src_ip, is_malicious=True)
        else:
            # Case B: MISP에 없지만 공격 행위 탐지 -> 의심 IP로 임시 차단 (선제적 방어)
            logger.info(f"[DECISION] IP {src_ip} is SUSPICIOUS. Applying Temporary Block (24h).")
            success = await pfsense.block_ip(ip=src_ip, is_malicious=False)

        # 5. 결과 로깅
        if success:
            logger.info(f"Successfully blocked {src_ip} on Firewall.")
        else:
            logger.error(f"Failed to block {src_ip} on Firewall.")

    except Exception as e:
        logger.error(f"Error executing reactive_ip_check playbook: {e}", exc_info=True)