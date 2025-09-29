"""
Execution time limit tracking for testplan.

This module provides a singleton to track execution time limits at the testplan level.
When the time limit is exceeded, further testcases should be marked as failed.
"""

import time
from typing import Optional


class ExecutionTimeLimitManager:
    """
    Singleton class to track testplan execution time limits.
    
    This manager tracks the start time and time limit for a testplan execution.
    It provides methods to check if the execution time has been exceeded before
    running each testcase.
    """
    
    _instance: Optional['ExecutionTimeLimitManager'] = None
    
    def __new__(cls) -> 'ExecutionTimeLimitManager':
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if not self._initialized:
            self.reset()
            self._initialized = True
    
    def reset(self):
        """Reset the time tracking state."""
        self._start_time: Optional[float] = None
        self._time_limit: Optional[float] = None
        self._limit_exceeded: bool = False
    
    def start_tracking(self, time_limit: Optional[float] = None):
        """
        Start tracking execution time with an optional time limit.
        
        Args:
            time_limit: Maximum execution time in seconds. If None, no limit is set.
        """
        self._start_time = time.time()
        self._time_limit = time_limit
        self._limit_exceeded = False
    
    def is_time_limit_exceeded(self) -> bool:
        """
        Check if the execution time limit has been exceeded.
        
        Returns:
            True if time limit is set and has been exceeded, False otherwise.
        """
        if self._time_limit is None or self._start_time is None:
            return False
        
        elapsed = time.time() - self._start_time
        if not self._limit_exceeded and elapsed >= self._time_limit:
            self._limit_exceeded = True
            return True
        
        return self._limit_exceeded
    
    def get_elapsed_time(self) -> float:
        """
        Get the elapsed execution time in seconds.
        
        Returns:
            Elapsed time in seconds, or 0.0 if tracking hasn't started.
        """
        if self._start_time is None:
            return 0.0
        return time.time() - self._start_time
    
    def get_time_limit(self) -> Optional[float]:
        """
        Get the current time limit.
        
        Returns:
            Time limit in seconds, or None if no limit is set.
        """
        return self._time_limit
    
    def get_remaining_time(self) -> Optional[float]:
        """
        Get the remaining time before the limit is exceeded.
        
        Returns:
            Remaining time in seconds, or None if no limit is set.
        """
        if self._time_limit is None or self._start_time is None:
            return None
        
        elapsed = self.get_elapsed_time()
        remaining = self._time_limit - elapsed
        return max(0.0, remaining)


# Global instance
execution_time_manager = ExecutionTimeLimitManager()