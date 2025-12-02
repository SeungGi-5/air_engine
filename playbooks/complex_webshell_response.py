import os
import logging
import asyncio
from typing import Dict, Any
from config import settings
from connectors.cape_connector import CapeConnector
from playbooks import reactive_ip_check
import zipfile

# 로거 설정
logger = logging.getLogger("Playbook:ComplexWebShellResponse")

# 환경 설정 (실무에서는 config.py에서 로드 권장)
DOWNLOAD_DIR = settings.DOWNLOAD_DIR
VM2_USER = settings.VM2_USER
VM2_IP = settings.VM2_IP
SSH_KEY_PATH = settings.SSH_KEY_PATH

async def download_file_scp(remote_path: str) -> str:
    """VM2에서 악성 의심 파일을 가져옴"""
    if not os.path.exists(DOWNLOAD_DIR):
        os.makedirs(DOWNLOAD_DIR)
    
    file_name = os.path.basename(remote_path)
    local_path = os.path.join(DOWNLOAD_DIR, file_name)
    
    cmd = f"scp -o StrictHostKeyChecking=no -i {SSH_KEY_PATH} {VM2_USER}@{VM2_IP}:{remote_path} {local_path}"
    
    proc = await asyncio.create_subprocess_shell(
        cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    await proc.communicate()
    
    if proc.returncode == 0 and os.path.exists(local_path):
        return local_path
    return None

async def delete_remote_file_ssh(remote_path: str) -> bool:
    """VM2의 악성 파일을 SSH 명령으로 삭제."""
    # 안전장치: 중요한 시스템 파일 삭제 방지 (간단한 검증)
    if not remote_path.startswith("/var/www"):
        logger.warning(f"Delete blocked for safety: {remote_path}")
        return False

    cmd = f"ssh -o StrictHostKeyChecking=no -i {SSH_KEY_PATH} {VM2_USER}@{VM2_IP} 'rm -f {remote_path}'" # rm -f 사용 시 sudo 필요 여부 확인 (secadmin 권한에 따라 다름)
    # 만약 삭제 권한이 부족하면 'sudo rm -f'를 써야 하며, sudoers NOPASSWD 설정 필요
    
    logger.info(f"Executing Remote Deletion: {remote_path}")
    proc = await asyncio.create_subprocess_shell(
        cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    await proc.communicate()
    
    return proc.returncode == 0

async def find_attacker_ip_ssh(file_name: str) -> str:
    """
    [IP 역추적] 웹 로그(access.log)를 뒤져서 해당 파일을 업로드(POST)한 IP를 찾아냄.
    명령어 로직: access.log에서 파일명이 포함된 줄을 찾고 -> 그 중 POST 요청을 찾고 -> 맨 앞의 IP를 추출
    """        
    grep_cmd = f"grep '{file_name}' /var/log/apache2/access.log | grep 'POST' | tail -n 1 | awk '{{print $1}}'"
    cmd = f"ssh -o StrictHostKeyChecking=no -i {SSH_KEY_PATH} {VM2_USER}@{VM2_IP} \"{grep_cmd}\""
    
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        if proc.returncode == 0:
            ip = stdout.decode().strip()
            if not ip:
                logger.info("Filename not found in logs. Trying upload page correlation...")
                # 최근 5분 내의 POST 업로드 요청 IP 추출
                grep_cmd_fallback = "grep 'POST .*/upload/' /var/log/apache2/integrated_access.log | tail -n 1 | cut -d ' ' -f 1"
                cmd_fallback = f"ssh -o StrictHostKeyChecking=no -i {SSH_KEY_PATH} {VM2_USER}@{VM2_IP} \"{grep_cmd_fallback}\""
                
                # (Fallback 실행 로직 추가)
                proc = await asyncio.create_subprocess_shell(
                    cmd_fallback, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()
                print(f"stdout-{stdout}")
                ip = stdout.decode().strip()
                print(f"ip-{ip}")
            # 유효한 IP 형식이 맞는지 간단 체크 (빈 문자열이 아니면 채택)
            if ip and len(ip.split('.')) == 4:
                logger.info(f"Found Attacker IP from Web Logs: {ip}")
                return ip
    except Exception as e:
        logger.error(f"Failed to find IP: {e}")
    
    return None


async def run(alert_data: Dict[str, Any]):
    try:
        # 1. 데이터 파싱 (파일 경로 & 공격자 IP)
        syscheck = alert_data.get('syscheck', {})
        remote_file_path = syscheck.get('path')
        
        # Wazuh FIM 로그에는 srcip가 없을 수 있음.
        # 200201(Auditd) 룰일 경우 audit 데이터에서 추출하거나, 웹로그와 연관 분석 필요.
        # 여기서는 Alert에 srcip 필드가 있다고 가정하거나, 없다면 방어적 차단 생략.
        src_ip = alert_data.get('data', {}).get('srcip')

        logger.info(f"Analyzing Threat: File={remote_file_path}, IP={src_ip}")

        if not remote_file_path:
            logger.warning("No file path found. Skipping file analysis.")
            return

        # 2. 파일 확보 및 CAPE 분석
        local_path = await download_file_scp(remote_file_path)
        
        is_malicious = False
        if local_path:
            cape = CapeConnector()
            task_id = await cape.submit_file(local_path)
            
            if task_id:
                logger.info(f"CAPE Analysis Started (Task ID: {task_id})")
                report = await cape.get_report(task_id)
                
                if report:
                    score = report.get('malware_score', 0)
                    is_malicious = report.get('is_malicious', False)
                    logger.info(f"CAPE Result: Score {score} (Malicious: {is_malicious})")
                    
                    # 점수가 높거나(5.0 이상) 명시적 악성이면 대응
                    if score >= 0:
                        is_malicious = True
                    if remote_file_path.endswith(".php") and "/var/www" in remote_file_path:
                        logger.warning("Low score but suspicious PHP in webroot. Treating as MALICIOUS.")
                        is_malicious = True

        # 3. 대응 실행 (파일 삭제 & IP 차단)
        if is_malicious:
            logger.warning("!!! Malicious File Detected. Initiating Countermeasures !!!")
            
            # 파일 삭제
            if await delete_remote_file_ssh(remote_file_path):
                logger.info(f"SUCCESS: Deleted malicious file {remote_file_path}")
            else:
                logger.error(f"FAILED: Could not delete file {remote_file_path}")
            attacker_ip = await find_attacker_ip_ssh(os.path.basename(remote_file_path))

            if attacker_ip:
                logger.info(f"Triggering IP Block for detected attacker: {attacker_ip}")
                # IP 차단 플레이북 호출 (데이터 구조를 맞춰서 전달)
                ip_alert_data = {"data": {"srcip": attacker_ip}, "rule": {"description": "Linked to WebShell Upload"}}
                await reactive_ip_check.run(ip_alert_data)
            else:
                logger.warning("Could not identify Attacker IP from logs.")
        else:
            logger.info("File determined to be SAFE or analysis failed.")

    except Exception as e:
        logger.error(f"Error in complex_webshell_response: {e}", exc_info=True)
    finally:
        # VM 3 로컬 파일 정리 (Clean up)
        if local_path and os.path.exists(local_path):
            try:
                os.remove(local_path)
                logger.info(f"Cleaned up local file: {local_path}")
            except Exception as cleanup_error:
                logger.error(f"Failed to clean up file: {cleanup_error}")