import json
import asyncio
import tempfile
import os
from typing import List, Dict, Any, Optional
from .base_connector import BaseConnector
import shlex
import urllib.parse

class NucleiConnector(BaseConnector):
    def __init__(self, nuclei_path: str = "/usr/local/bin/nuclei"):
        super().__init__()
        self.nuclei_path = nuclei_path

    async def health_check(self) -> bool:
        """Nuclei 실행 가능 여부 확인"""
        try:
            proc = await asyncio.create_subprocess_exec(
                self.nuclei_path, "-version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            return proc.returncode == 0
        except FileNotFoundError:
            self.logger.critical("Nuclei binary not found.")
            return False
        
    def _extract_payload_from_curl(self, curl_cmd: str) -> str:
        """
        curl 명령어에서 POST data(-d) 부분을 추출하고 URL Decode를 수행
        가상 패치(WAF Rule) 생성 시 공격 패턴을 식별하기 위해 필요
        """
        if not curl_cmd:
            return ""
        
        try:
            # shlex를 사용하여 쉘 명령어를 안전하게 토큰화 (따옴표 처리 등)
            tokens = shlex.split(curl_cmd)
            
            # -d 또는 --data 플래그 탐색
            for i, token in enumerate(tokens):
                if token in ("-d", "--data", "--data-raw", "--data-binary") and i + 1 < len(tokens):
                    raw_payload = tokens[i+1]
                    # URL Decoding 수행 (예: %257b -> %{ )
                    decoded_payload = urllib.parse.unquote(raw_payload)
                    # 이중 인코딩된 경우가 많으므로 한 번 더 시도 (Safe check)
                    if "%" in decoded_payload:
                        decoded_payload = urllib.parse.unquote(decoded_payload)
                    return decoded_payload
            
            return ""
        except Exception as e:
            self.logger.warning(f"Failed to extract payload from curl command: {e}")
            return ""

    def parse_vulnerability(self, raw_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Nuclei Raw JSON 데이터에서 필요한 핵심 정보만 추출하여 정제
        """
        try:
            # 기본 필드 추출
            template_id = raw_data.get('template-id', 'Unknown')
            info = raw_data.get('info', {})
            severity = info.get('severity', 'low')
            matched_at = raw_data.get('matched-at', '')
            curl_command = raw_data.get('curl-command', '')
            
            # 공격 구문(Payload) 추출
            # 1순위: curl 명령어의 데이터 필드 분석
            request_payload = self._extract_payload_from_curl(curl_command)
            
            # 2순위: curl 파싱 실패 시, request 원문 사용 (너무 길 경우 잘라냄)
            if not request_payload and 'request' in raw_data:
                request_payload = raw_data['request'][:2000] # 길이 제한

            # 결과 객체 생성
            parsed_vuln = {
                "cve_id": template_id,
                "severity": severity,
                "target_url": matched_at,
                "curl_command": curl_command,
                "attack_pattern": request_payload, # 공격 시그니처(Pattern) 추출 
                "description": info.get('description', ''),
                "remediation": info.get('remediation', '')
            }
            return parsed_vuln

        except Exception as e:
            self.logger.error(f"Error parsing vulnerability data: {e}", exc_info=True)
            return None
        
    @BaseConnector.safe_execution
    async def scan_target(self, target_ip: str) -> List[Dict[str, Any]]:
        results = []
        # 임시 파일을 생성하여 JSON 결과 저장 (메모리 오버헤드 방지)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_file:
            output_path = tmp_file.name

        try:
            # 실무적 옵션: -severity critical,high (오탐 및 노이즈 감소)
            cmd = [
                self.nuclei_path,
                "-u", target_ip,
                "-irr",
                "-severity", "critical,high",
                "-je", output_path,
                "-silent"  # 불필요한 배너 출력 제거
            ]

            self.logger.info(f"Starting Nuclei scan on {target_ip} with high/critical severity filter.")
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                self.logger.error(f"Nuclei scan failed: {stderr.decode()}")
                return []

            # JSON 결과 파싱 (nuclei_스캔결과.txt 구조 반영)
            # Nuclei는 라인 단위로 JSON 객체를 기록함 (NDJSON)
            if os.path.exists(output_path):
                with open(output_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.strip():
                            try:
                                vuln_data = json.loads(line)
                                parsed_data = [ self.parse_vulnerability(i) for i in vuln_data ]
                                if parsed_data:
                                    results.extend(parsed_data)
                            except json.JSONDecodeError:
                                self.logger.warning(f"Skipping invalid JSON line: {line[:50]}...")
                                continue
            
            self.logger.info(f"Scan complete. Found {len(results)} vulnerabilities.")
            return results

        except Exception as e:
            self.logger.error(f"Exception during Nuclei scan: {e}")
            return []
        finally:
            if os.path.exists(output_path):
                try:
                    os.remove(output_path)
                except OSError:
                    pass