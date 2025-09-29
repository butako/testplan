#!/usr/bin/env python
"""Testplan that tests execution time limit functionality."""

import sys
import time

from testplan import test_plan
from testplan.testing import multitest


@multitest.testsuite
class FastSuite:
    @multitest.testcase
    def fast_case1(self, env, result):
        result.log("Fast testcase 1")
        result.equal(1, 1)

    @multitest.testcase
    def fast_case2(self, env, result):
        result.log("Fast testcase 2")
        result.equal(2, 2)


@multitest.testsuite
class SlowSuite:
    @multitest.testcase
    def slow_case1(self, env, result):
        result.log("Slow testcase - will exceed time limit")
        time.sleep(2)  # This will consume time
        result.equal(3, 3)

    @multitest.testcase
    def slow_case2(self, env, result):
        result.log("This should be marked as failed due to time limit")
        result.equal(4, 4)


@test_plan(name="Execution Time Limit Test", execution_time_limit=1.5)
def main(plan):
    plan.add(multitest.MultiTest(name="Fast MTest", suites=[FastSuite()]))
    plan.add(multitest.MultiTest(name="Slow MTest", suites=[SlowSuite()]))


if __name__ == "__main__":
    sys.exit(main().exit_code)