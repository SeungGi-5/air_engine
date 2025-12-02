import logging
import asyncio
from abc import ABC, abstractmethod
from typing import Any, Callable
from functools import wraps

# 로거 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class BaseConnector(ABC):
    """
    모든 커넥터의 추상 기본 클래스
    공통 로깅 및 예외 처리 로직을 제공
    """
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    @staticmethod
    def safe_execution(func: Callable) -> Callable:
        """
        메서드 실행 중 발생하는 예외를 로깅하고 None을 반환하는 데코레이터
        """
        @wraps(func)
        async def wrapper(self, *args, **kwargs):
            try:
                if asyncio.iscoroutinefunction(func):
                    return await func(self, *args, **kwargs)
                else:
                    return func(self, *args, **kwargs)
            except Exception as e:
                self.logger.error(f"Error in {func.__name__}: {str(e)}", exc_info=True)
                raise e # 상위 로직에서 핸들링할 수 있도록 raise, 혹은 return None
        return wrapper

    @abstractmethod
    async def health_check(self) -> bool:
        """연결 상태를 점검하는 추상 메서드"""
        pass