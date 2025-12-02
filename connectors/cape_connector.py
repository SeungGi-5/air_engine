import os
import aiohttp
import asyncio
import ssl
import json
from typing import Optional, Dict, Any, List
from config import settings
from .base_connector import BaseConnector

class CapeConnector(BaseConnector):
    """
    CAPE Sandbox (v2 API) 비동기 연동 커넥터
    기능: 파일 분석 제출, 상태 모니터링, 결과 리포트 파싱
    """
    def __init__(self):
        super().__init__()
        # 설정 로드 (.env / config.py)
        self.api_url = settings.CAPE_URL.rstrip('/')
        self.api_key = settings.CAPE_API_KEY
        
        # CAPE API 인증 헤더 (Token 방식)
        self.headers = {
            "Authorization": f"Token {self.api_key}"
        }

        # 내부망(사설인증서) 환경을 위한 SSL 검증 무시 설정
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

        # 분석 대기 시간 설정 (초)
        self.ANALYSIS_TIMEOUT = 600  # 최대 10분 대기
        self.POLLING_INTERVAL = 15   # 15초마다 상태 확인

    async def health_check(self) -> bool:
        """CAPE 서버 상태 및 API 연결 확인"""
        endpoint = f"{self.api_url}/cuckoo/status/"
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=self.ssl_context)) as session:
                async with session.get(endpoint, headers=self.headers, timeout=5) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        # 작업 큐가 너무 밀려있지 않은지 확인
                        pending = data.get('tasks', {}).get('pending', 0)
                        self.logger.info(f"CAPE Connected. Pending Tasks: {pending}")
                        return True
                    return False
        except Exception as e:
            self.logger.error(f"CAPE Health Check Failed: {e}")
            return False

    @BaseConnector.safe_execution
    async def submit_file(self, file_path: str, machine: str = None, platform: str = "windows", **kwargs) -> Optional[int]:
        """
        로컬 파일을 CAPE에 제출하고 Task ID를 반환
        
        Args:
            file_path: 분석할 파일의 절대 경로
            machine: 특정 VM 지정 (없으면 자동 할당)
            platform: 'windows', 'linux' 등
            **kwargs: tags, package, options 등 추가 파라미터
        Returns:
            task_id (int) or None
        """
        if not os.path.exists(file_path):
            self.logger.error(f"File not found: {file_path}")
            return None

        endpoint = f"{self.api_url}/tasks/create/file/"
        
        # Multipart 데이터 구성
        data = aiohttp.FormData()
        data.add_field('file', open(file_path, 'rb'), filename=os.path.basename(file_path))
        data.add_field('platform', platform)
        
        if machine:
            data.add_field('machine', machine)

        # 추가 옵션 처리 (예: timeout, priority 등)
        for key, value in kwargs.items():
            if value:
                data.add_field(key, str(value))

        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=self.ssl_context)) as session:
                self.logger.info(f"Submitting file to CAPE: {os.path.basename(file_path)}")
                async with session.post(endpoint, headers=self.headers, data=data) as resp:
                    if resp.status == 200:
                        resp_json = await resp.json()
                        if resp_json.get('error')==True:
                            self.logger.error(f"Submission failed. Status: {resp_json.get('errors')}")
                            return None
                        data_block = resp_json.get('data', {})
                        task_ids_list = data_block.get('task_ids', [])
                        if task_ids_list:
                            task_id = task_ids_list[0] # 리스트의 첫 번째 ID 추출
                        self.logger.info(f"File submitted successfully. Task ID: {task_id}")
                        return task_id
                    else:
                        self.logger.error(f"Submission failed. Status: {resp.status}, Msg: {await resp.text()}")
                        return None
        except Exception as e:
            self.logger.error(f"Error submitting file to CAPE: {e}")
            return None

    async def _wait_for_analysis(self, task_id: int) -> bool:
        """
        분석이 완료될 때까지 상태를 주기적으로 조회(Polling).
        상태: pending -> running -> reported
        """
        endpoint = f"{self.api_url}/tasks/view/{task_id}/"
        start_time = asyncio.get_event_loop().time()

        while (asyncio.get_event_loop().time() - start_time) < self.ANALYSIS_TIMEOUT:
            try:
                async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=self.ssl_context)) as session:
                    async with session.get(endpoint, headers=self.headers) as resp:
                        if resp.status != 200:
                            self.logger.warning(f"Failed to check task status. Code: {resp.status}")
                            await asyncio.sleep(self.POLLING_INTERVAL)
                            continue

                        data = await resp.json()
                        status = data.get('data', {}).get('status')
                        
                        if status == 'reported':
                            self.logger.info(f"Task {task_id} analysis completed.")
                            return True
                        elif status == 'failed_analysis':
                            self.logger.error(f"Task {task_id} failed during analysis.")
                            return False
                        self.logger.info(f"Task {task_id} Current Status: {status}")
                        
                        # 진행 중이면 대기
                        self.logger.debug(f"Task {task_id} status: {status}. Waiting...")
                        await asyncio.sleep(self.POLLING_INTERVAL)

            except Exception as e:
                self.logger.error(f"Error polling status for task {task_id}: {e}")
                await asyncio.sleep(self.POLLING_INTERVAL)

        self.logger.error(f"Task {task_id} timed out after {self.ANALYSIS_TIMEOUT} seconds.")
        return False

    def _parse_report_summary(self, report: Dict) -> Dict[str, Any]:
        summary = {
            "malware_score": 0.0,
            "malware_family": "Unknown",
            "detections": [],
            "is_malicious": False
        }

        try:
            # 1. Malware Score 추출
            if 'malscore' in report:
                summary['malware_score'] = float(report['malscore'])
            # 예비: info 섹션 내부의 score 확인
            elif 'info' in report and 'score' in report['info']:
                summary['malware_score'] = float(report['info']['score'])

            # 2. 탐지된 시그니처 (Signatures) 추출
            signatures = report.get('signatures', [])
            for sig in signatures:
                # 노이즈를 줄이기 위해 severity 1 이상만 수집
                if sig.get('severity', 0) >= 1:
                    summary['detections'].append({
                        "name": sig.get('name', 'Unknown'),
                        "severity": sig.get('severity', 0),
                        "description": sig.get('description', '')
                    })

            # 3. 악성 패밀리 정보 (Malware Family)
            cape_section = report.get('CAPE', {})
            configs = cape_section.get('configs', [])
            network = report.get('network', {})
            
            if configs:
                # 설정 파일에서 패밀리명 추출
                summary['malware_family'] = configs[0].get('family', 'Unknown')
            

            # 4. 최종 악성 여부 판단 (Thresholding)
            # 점수가 5.0 이상이거나, 심각도 높은 시그니처가 있으면 악성으로 간주
            if summary['malware_score'] >= 5.0:
                summary['is_malicious'] = True
            
            # 점수가 낮더라도 치명적인 시그니처(예: Ransomware behavior)가 있으면 악성
            for det in summary['detections']:
                if det['severity'] >= 3:
                    summary['is_malicious'] = True
                    break

        except Exception as e:
            self.logger.error(f"Error parsing CAPE report summary: {e}")

        return summary

    @BaseConnector.safe_execution
    async def get_report(self, task_id: int) -> Optional[Dict[str, Any]]:
        """
        분석 완료를 대기하고 최종 요약 리포트를 반환합니다.
        """
        # 1. 분석 완료 대기
        is_finished = await self._wait_for_analysis(task_id)
        if not is_finished:
            return None

        # 2. 리포트 다운로드
        endpoint = f"{self.api_url}/tasks/get/report/{task_id}/json/"
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=self.ssl_context)) as session:
                # 리포트 용량이 클 수 있으므로 충분한 타임아웃 설정
                async with session.get(endpoint, headers=self.headers, timeout=60) as resp:
                    if resp.status == 200:
                        full_report = await resp.json()
                        # 3. 핵심 정보 파싱 후 반환
                        return self._parse_report_summary(full_report)
                    else:
                        self.logger.error(f"Failed to get report for {task_id}. Status: {resp.status}")
                        return None
        except Exception as e:
            self.logger.error(f"Error retrieving report for {task_id}: {e}")
            return None