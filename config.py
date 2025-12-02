import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    # pfSense
    PFSENSE_API_URL: str = os.getenv("PFSENSE_API_URL", "")
    PFSENSE_API_KEY: str = os.getenv("PFSENSE_API_KEY", "")
    PFSENSE_VERIFY_SSL: bool = os.getenv("PFSENSE_VERIFY_SSL", "false").lower() == "true"
    MISP_URL: str = os.getenv("MISP_URL", "")
    MISP_API_KEY: str = os.getenv("MISP_API_KEY", "")
    CAPE_URL: str = os.getenv("CAPE_URL", "")
    CAPE_API_KEY: str = os.getenv("CAPE_API_KEY", "")
    DOWNLOAD_DIR: str = os.getenv("DOWNLOAD_DIR", "")
    VM2_USER: str = os.getenv("VM2_USER", "")
    VM2_IP: str = os.getenv("VM2_IP", "")
    SSH_KEY_PATH: str = os.getenv("SSH_KEY_PATH", "")
    NESTED_VM: str = os.getenv("NESTED_VM", "")

settings = Settings()
