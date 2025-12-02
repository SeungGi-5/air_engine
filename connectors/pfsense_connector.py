from config import settings
import aiohttp
import ssl
import base64
import json
from typing import List, Optional
from .base_connector import BaseConnector

class PfSenseConnector(BaseConnector):
    def __init__(self):
        super().__init__()
        self.api_url = settings.PFSENSE_API_URL.rstrip('/')
        
        # Basic Auth 헤더 생성
        self.api_key = settings.PFSENSE_API_KEY
        
        self.headers = {
            "x-api-key": self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

        # 차단용 Alias 이름 정의
        self.ALIAS_PERMANENT = "AIR_Permanent_Blacklist"
        self.ALIAS_TEMP = "AIR_Temp_Blocklist"

    async def health_check(self) -> bool:
        """연결 상태 확인"""
        endpoint = f"{self.api_url}/api/v2/status/system"
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=self.ssl_context)) as session:
                async with session.get(endpoint, headers=self.headers, timeout=5) as resp:
                    return resp.status == 200
        except Exception as e:
            self.logger.error(f"pfSense Health Check failed: {e}")
            return False

    async def _get_current_alias_ips(self, session, alias_name: str) -> Optional[List[str]]:
        """
        특정 Alias의 현재 IP 목록을 조회합니다.
        Alias가 없으면 None을 반환합니다.
        """
        endpoint = f"{self.api_url}/api/v2/firewall/aliases"
        try:
            # 모든 Alias를 가져와서 필터링 (API가 필터링을 지원하지 않는 경우 대비)
            # API가 ?name= 지원 시 최적화 가능
            async with session.get(endpoint, headers=self.headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    # 응답 구조가 {'data': [...]} 또는 리스트[...] 형태일 수 있음
                    aliases = data.get('data', []) if isinstance(data, dict) else data
                    
                    for alias in aliases:
                        if alias.get('name') == alias_name:
                            return {alias.get('id', str):alias.get('address', [])}
                    return None # Alias not found
                else:
                    self.logger.error(f"Failed to fetch aliases. Status: {resp.status}")
                    return None
        except Exception as e:
            self.logger.error(f"Error fetching alias {alias_name}: {e}")
            return None

    async def block_ip(self, ip: str, is_malicious: bool = False) -> bool:
        """
        IP를 차단합니다.
        1. Alias 존재 여부 확인
        2. 없으면 POST로 생성
        3. 있으면 기존 목록에 추가하여 PATCH로 업데이트 (Read-Modify-Write)
        """
        target_alias = self.ALIAS_PERMANENT if is_malicious else self.ALIAS_TEMP
        description = "A.I.R. Permanent Block" if is_malicious else "A.I.R. Temp Block (24h)"
        endpoint = f"{self.api_url}/api/v2/firewall/alias"

        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=self.ssl_context)) as session:
            # 1. 현재 Alias 상태 조회
            current = await self._get_current_alias_ips(session, target_alias)
            current_ips = list(current.values())[0]
            current_id = list(current.keys())[0]

            # Case A: Alias가 아예 없는 경우 -> POST로 신규 생성
            if current is None:
                self.logger.info(f"Alias {target_alias} not found. Creating new...")
                payload = {
                    "name": target_alias,
                    "type": "host",
                    "address": [ip],
                    "descr": description,
                    "detail": f"Blocked IP: {ip}",
                    "apply": True
                }
                async with session.post(endpoint, json=payload, headers=self.headers) as resp:
                    if resp.status in [200, 201]:
                        self.logger.info(f"Created alias {target_alias} with IP {ip}")
                        return True
                    else:
                        self.logger.error(f"Failed to create alias. {await resp.text()}")
                        return False

            # Case B: Alias가 존재하는 경우 -> PATCH로 업데이트
            else:
                if ip in current_ips:
                    self.logger.info(f"IP {ip} already exists in {target_alias}. Skipping.")
                    return True

                # 기존 목록에 추가 (Append)
                current_ips.append(ip)
                
                # PATCH 요청: 전체 리스트를 다시 보내야 함 (API 특성에 따라 다를 수 있으나 이게 안전함)
                # v2 API 명세에 따라 식별자(name 또는 id)를 지정해야 함
                payload = {
                    "id":current_id,
                    "name": target_alias, # 식별자
                    "address": current_ips,
                    "type": "host",
                    "apply": True
                }
                
                self.logger.info(f"Updating {target_alias}: Adding {ip} (Total: {len(current_ips)})")
                
                # PATCH 메소드 사용
                async with session.patch(endpoint, json=payload, headers=self.headers) as resp:
                    if resp.status in [200, 201]:
                        self.logger.info(f"Successfully added {ip} to {target_alias}")
                        return True
                    else:
                        text = await resp.text()
                        self.logger.error(f"Failed to update alias. Status: {resp.status}, Body: {text}")
                        return False