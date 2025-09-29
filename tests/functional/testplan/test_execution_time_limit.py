import json
import os
import subprocess
import sys
import tempfile

import psutil


def test_execution_time_limit():
    """
    Tests the testplan execution time limit feature.
    """
    testplan_script = os.path.join(
        os.path.dirname(__file__), "execution_time_limit_test_plan.py"
    )
    assert os.path.isfile(testplan_script)

    current_proc = psutil.Process()
    start_procs = current_proc.children()

    output_json = tempfile.NamedTemporaryFile(suffix=".json").name

    try:
        proc = subprocess.Popen(
            [sys.executable, testplan_script, "--json", output_json],
            stdout=subprocess.PIPE,
            universal_newlines=True,
        )

        # Set our own timeout so that we don't wait forever if the testplan
        # script fails to complete. 1 minute ought to be long enough.
        try:
            proc.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()

        rc = proc.returncode

        with open(output_json, "r") as json_file:
            report = json.load(json_file)

        # Check that the testplan exited with an error status because of failed testcases.
        assert rc == 1
        
        # Check that we have 2 MultiTest entries
        assert len(report["entries"]) == 2
        
        # First MultiTest (Fast MTest) should have passed
        fast_mtest = report["entries"][0]
        assert fast_mtest["name"] == "Fast MTest"
        assert fast_mtest["status"] == "passed"
        
        # Second MultiTest (Slow MTest) should have failed due to time limit
        slow_mtest = report["entries"][1]
        assert slow_mtest["name"] == "Slow MTest"
        assert slow_mtest["status"] == "failed"
        
        # Check that at least one testcase has the time limit exceeded message
        slow_suite = slow_mtest["entries"][0]  # SlowSuite
        time_limit_found = False
        
        for testcase in slow_suite["entries"]:
            for entry in testcase.get("entries", []):
                if (entry.get("type") == "Fail" and 
                    "time limit" in entry.get("message", "").lower()):
                    time_limit_found = True
                    break
        
        assert time_limit_found, "Expected to find time limit exceeded assertion"

        # Check that no extra child processes remain since before starting.
        assert current_proc.children() == start_procs

    finally:
        if os.path.exists(output_json):
            os.remove(output_json)