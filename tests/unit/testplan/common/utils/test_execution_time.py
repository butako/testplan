import time

import pytest

from testplan.common.utils.execution_time import ExecutionTimeLimitManager, execution_time_manager


class TestExecutionTimeLimitManager:
    def test_singleton_behavior(self):
        """Test that ExecutionTimeLimitManager is a singleton."""
        manager1 = ExecutionTimeLimitManager()
        manager2 = ExecutionTimeLimitManager()
        assert manager1 is manager2
        assert manager1 is execution_time_manager

    def test_reset(self):
        """Test the reset functionality."""
        manager = ExecutionTimeLimitManager()
        manager.start_tracking(10.0)
        
        # Reset should clear all state
        manager.reset()
        assert manager.get_time_limit() is None
        assert manager.get_elapsed_time() == 0.0
        assert not manager.is_time_limit_exceeded()

    def test_start_tracking_without_limit(self):
        """Test starting tracking without a time limit."""
        manager = ExecutionTimeLimitManager()
        manager.reset()
        
        manager.start_tracking(None)
        assert manager.get_time_limit() is None
        assert not manager.is_time_limit_exceeded()
        assert manager.get_remaining_time() is None

    def test_start_tracking_with_limit(self):
        """Test starting tracking with a time limit."""
        manager = ExecutionTimeLimitManager()
        manager.reset()
        
        time_limit = 5.0
        manager.start_tracking(time_limit)
        
        assert manager.get_time_limit() == time_limit
        assert not manager.is_time_limit_exceeded()
        assert manager.get_remaining_time() is not None
        assert manager.get_remaining_time() <= time_limit

    def test_time_limit_exceeded(self):
        """Test time limit exceeded detection."""
        manager = ExecutionTimeLimitManager()
        manager.reset()
        
        # Start with a very short time limit
        manager.start_tracking(0.1)
        
        # Sleep to exceed the time limit
        time.sleep(0.2)
        
        # Should detect time limit exceeded
        assert manager.is_time_limit_exceeded()
        
        # Should remain exceeded on subsequent calls
        assert manager.is_time_limit_exceeded()

    def test_elapsed_time_tracking(self):
        """Test elapsed time tracking."""
        manager = ExecutionTimeLimitManager()
        manager.reset()
        
        manager.start_tracking(10.0)
        initial_elapsed = manager.get_elapsed_time()
        
        time.sleep(0.1)
        
        later_elapsed = manager.get_elapsed_time()
        assert later_elapsed > initial_elapsed
        assert later_elapsed >= 0.1

    def test_remaining_time_calculation(self):
        """Test remaining time calculation."""
        manager = ExecutionTimeLimitManager()
        manager.reset()
        
        time_limit = 1.0
        manager.start_tracking(time_limit)
        
        remaining = manager.get_remaining_time()
        assert remaining is not None
        assert remaining <= time_limit
        
        time.sleep(0.1)
        
        new_remaining = manager.get_remaining_time()
        assert new_remaining < remaining

    def test_remaining_time_never_negative(self):
        """Test that remaining time never goes below zero."""
        manager = ExecutionTimeLimitManager()
        manager.reset()
        
        # Start with a very short time limit
        manager.start_tracking(0.05)
        
        # Sleep to exceed the time limit
        time.sleep(0.1)
        
        remaining = manager.get_remaining_time()
        assert remaining == 0.0