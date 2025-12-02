import aiohttp
import ssl
import json
from typing import Optional, Dict, Any
from config import settings
from .base_connector import BaseConnector

class MispConnector(BaseConnector):
    def __init__(self):
        super().__init__()
        self.base_url = settings.MISP_URL.rstrip('/')
        self.api_key = settings.MISP_API_KEY
        
        self.headers = {
            "Authorization": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

        # 내부망/사설인증서 환경을 위한 SSL Context 설정
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

    async def health_check(self) -> bool:
        """MISP 서버 연결 상태 확인"""
        url = f"{self.base_url}/servers/getVersion"
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=self.ssl_context)) as session:
                async with session.get(url, headers=self.headers, timeout=5) as resp:
                    return resp.status == 200
        except Exception as e:
            self.logger.error(f"MISP Health Check failed: {e}")
            return False

    @BaseConnector.safe_execution
    async def check_ip_reputation(self, ip: str) -> bool:
        """
        특정 IP가 MISP에 등록된 위협 IP(IOC)인지 조회.
        
        Args:
            ip (str): 조회할 IP 주소
        Returns:
            bool: 위협 정보가 존재하면 True, 없으면 False
        """
        # MISP restSearch 엔드포인트 사용
        url = f"{self.base_url}/attributes/restSearch"
        
        # 검색 페이로드 구성
        payload = {
            "returnFormat": "json",
            "value": ip,
            "limit": 1 # 존재 여부만 확인하면 되므로 1개만 요청
        }

        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=self.ssl_context)) as session:
                async with session.post(url, headers=self.headers, json=payload, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        # 'response' 키 안에 'Attribute' 리스트가 존재하면 IOC로 판단
                        attributes = data.get('response', {}).get('Attribute', [])
                        if attributes:
                            self.logger.warning(f"[MISP] IP {ip} found in Threat Intelligence! (Count: {len(attributes)})")
                            return True
                        else:
                            self.logger.info(f"[MISP] IP {ip} is clean (No match found).")
                            return False
                    else:
                        self.logger.error(f"MISP API Error: {resp.status} - {await resp.text()}")
                        return False
                        
        except Exception as e:
            self.logger.error(f"Error checking IP reputation in MISP: {e}")
            return False