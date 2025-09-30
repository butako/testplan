"""Tests runner module."""

import inspect
import math
import os
import random
import re
import sys
import time
import traceback
import uuid
import webbrowser
from collections import OrderedDict
from copy import copy, deepcopy
from dataclasses import dataclass
from itertools import zip_longest
from traceback import format_stack
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Collection,
    Dict,
    List,
    MutableMapping,
    Optional,
    Pattern,
    Tuple,
    Union,
)

from schema import And, Or, Use

from testplan import defaults
from testplan.common.config import ConfigOption
from testplan.common.entity import (
    Resource,
    Runnable,
    RunnableConfig,
    RunnableResult,
    RunnableStatus,
)
from testplan.common.exporters import BaseExporter, ExportContext, run_exporter

if TYPE_CHECKING:
    from testplan.common.remote.remote_service import RemoteService
    from testplan.monitor.resource import (
        ResourceMonitorServer,
        ResourceMonitorClient,
    )

from testplan.common.report import MergeError
from testplan.common.utils import logger, strings
from testplan.common.utils.package import import_tmp_module
from testplan.common.utils.path import default_runpath, makedirs, makeemptydirs
from testplan.common.utils.selector import Expr as SExpr
from testplan.common.utils.selector import apply_single
from testplan.environment import EnvironmentCreator, Environments
from testplan.exporters import testing as test_exporters
from testplan.exporters.testing.base import Exporter
from testplan.exporters.testing.failed_tests import FailedTestLevel
from testplan.report import (
    ReportCategories,
    Status,
    TestCaseReport,
    TestGroupReport,
    TestReport,
)
from testplan.report.filter import ReportingFilter
from testplan.report.testing.styles import Style
from testplan.runners.base import Executor
from testplan.runners.pools.base import Pool
from testplan.runners.pools.tasks import Task, TaskResult
from testplan.runners.pools.tasks.base import (
    TaskTargetInformation,
    is_task_target,
)
from testplan.testing import common, filtering, listing, ordering, tagging
from testplan.testing.result import Result
from testplan.testing.base import Test, TestResult
from testplan.testing.listing import Lister
from testplan.testing.multitest import MultiTest

if sys.version_info < (3, 11):
    from exceptiongroup import ExceptionGroup

TestTask = Union[Test, Task, Callable]


MULTITEST_EXEC_TIME_ADJUST_FACTOR_LB = 0.25


@dataclass
class TaskInformation:
    target: TestTask
    materialized_test: Test
    uid: str
    task_arguments: dict
    num_of_parts: int


def get_exporters(values):
    """
    Validation function for exporter declarations.

    :param values: Single or a list of exporter declaration(s).
    :return: List of initialized exporter objects.
    """

    def get_exporter(value):
        if isinstance(value, BaseExporter):
            return value
        elif isinstance(value, tuple):
            exporter_cls, params = value
            return exporter_cls(**params)
        raise TypeError("Invalid exporter value: {}".format(value))

    if values is None:
        return []
    elif isinstance(values, list):
        return [get_exporter(v) for v in values]
    return [get_exporter(values)]


def result_for_failed_task(original_result):
    """
    Create a new result entry for invalid result retrieved from a resource.
    """
    result = TestResult()
    result.report = TestGroupReport(
        name=str(original_result.task), category=ReportCategories.ERROR
    )
    attrs = [attr for attr in original_result.task.serializable_attrs]
    result_lines = [
        "{}: {}".format(attr, getattr(original_result.task, attr))
        if getattr(original_result.task, attr, None)
        else ""
        for attr in attrs
    ]
    result.report.logger.error(
        os.linesep.join([line for line in result_lines if line])
    )
    result.report.logger.error(original_result.reason)
    result.report.status_override = Status.ERROR
    return result


def validate_lines(d: dict) -> bool:
    for v in d.values():
        if not (
            isinstance(v, list) and all(map(lambda x: isinstance(x, int), v))
        ) and not (isinstance(v, str) and v.strip() == "*"):
            raise ValueError(
                f'Unexpected value "{v}" of type {type(v)} for lines, '
                'list of integer or string literal "*" expected.'
            )
    return True


def check_local_server(browse):
    """
    Early exit if local server (`interactive` extra) is not installed when user
    asks for displaying report using local server feature.
    """
    if browse:
        from testplan.web_ui.web_app import WebServer

        del WebServer

    return True


def collate_for_merging(
    es: List[Union[TestGroupReport, TestCaseReport]],
) -> List[List[Union[TestGroupReport, TestCaseReport]]]:
    """
    Group report entries into buckets, where synthesized ones in the same
    bucket containing the previous non-synthesized one.
    """
    res = []
    i, j = 0, 0
    while i < len(es):
        if i < j:
            i += 1
            continue

        grp = [es[i]]
        j = i + 1
        while j < len(es):
            if es[j].category == ReportCategories.SYNTHESIZED:
                grp.append(es[j])
                j += 1
            else:
                break

        res.append(grp)
        i += 1

    return res


class TestRunnerConfig(RunnableConfig):
    """
    Configuration object for
    :py:class:`~testplan.runnable.TestRunner` runnable object.
    """

    ignore_extra_keys = True

    @classmethod
    def get_options(cls):
        return {
            "name": str,
            ConfigOption("description", default=None): Or(str, None),
            ConfigOption("logger_level", default=logger.USER_INFO): int,
            ConfigOption("file_log_level", default=logger.DEBUG): int,
            ConfigOption("runpath", default=default_runpath): Or(
                None, str, lambda x: callable(x)
            ),
            ConfigOption("path_cleanup", default=True): bool,
            ConfigOption("all_tasks_local", default=False): bool,
            ConfigOption(
                "shuffle", default=[]
            ): list,  # list of string choices
            ConfigOption(
                "shuffle_seed", default=float(random.randint(1, 9999))
            ): float,
            ConfigOption("exporters", default=None): Use(get_exporters),
            ConfigOption("stdout_style", default=defaults.STDOUT_STYLE): Style,
            ConfigOption("report_dir", default=defaults.REPORT_DIR): Or(
                str, None
            ),
            ConfigOption("xml_dir", default=None): Or(str, None),
            ConfigOption("pdf_path", default=None): Or(str, None),
            ConfigOption("json_path", default=None): Or(str, None),
            ConfigOption("http_url", default=None): Or(str, None),
            ConfigOption("dump_failed_tests", default=None): Or(str, None),
            ConfigOption(
                "failed_tests_level", default=defaults.FAILED_TESTS_LEVEL
            ): FailedTestLevel,
            ConfigOption("pdf_style", default=defaults.PDF_STYLE): Style,
            ConfigOption("report_tags", default=[]): [
                Use(tagging.validate_tag_value)
            ],
            ConfigOption("report_tags_all", default=[]): [
                Use(tagging.validate_tag_value)
            ],
            ConfigOption("merge_scheduled_parts", default=False): bool,
            ConfigOption("browse", default=False): bool,
            ConfigOption("ui_port", default=None): Or(
                None, And(int, check_local_server)
            ),
            ConfigOption(
                "web_server_startup_timeout",
                default=defaults.WEB_SERVER_TIMEOUT,
            ): int,
            ConfigOption(
                "test_filter", default=filtering.Filter()
            ): filtering.BaseFilter,
            ConfigOption(
                "test_sorter", default=ordering.NoopSorter()
            ): ordering.BaseSorter,
            # Test lister is None by default, otherwise Testplan would
            # list tests, not run them
            ConfigOption("test_lister", default=None): Or(
                None, listing.BaseLister, listing.MetadataBasedLister
            ),
            ConfigOption("test_lister_output", default=None): Or(str, None),
            ConfigOption("verbose", default=False): bool,
            ConfigOption("debug", default=False): bool,
            ConfigOption("timeout", default=defaults.TESTPLAN_TIMEOUT): Or(
                None, And(int, lambda t: t >= 0)
            ),
            # active_loop_sleep impacts cpu usage in interactive mode
            ConfigOption("active_loop_sleep", default=0.05): float,
            ConfigOption(
                "interactive_handler",
                default=None,
            ): object,
            ConfigOption("extra_deps", default=[]): [
                Or(str, lambda x: inspect.ismodule(x))
            ],
            ConfigOption("label", default=None): Or(None, str),
            ConfigOption("tracing_tests", default=None): Or(
                And(dict, validate_lines),
                None,
            ),
            ConfigOption("tracing_tests_output", default="-"): str,
            ConfigOption("resource_monitor", default=False): bool,
            ConfigOption("reporting_exclude_filter", default=None): Or(
                And(str, Use(ReportingFilter.parse)), None
            ),
            ConfigOption("xfail_tests", default=None): Or(dict, None),
            # Historical runtime data used for auto-partitioning and smart scheduling.
            # This dictionary contains execution time information (setup, execution, teardown)
            # for each test, enabling intelligent task distribution across pool workers.
            ConfigOption("runtime_data", default={}): Or(dict, None),
            # Maximum runtime allowed for each auto-partitioned task part (in seconds).
            # When set to a numeric value (int/float), tasks exceeding this limit will be
            # automatically split into smaller parts to ensure balanced execution.
            # When set to "auto", the system calculates an optimal limit based on:
            #   - Historical runtime data from previous test runs
            #   - MultiTest setup/teardown overhead
            #   - Unit test total runtime
            # Default: AUTO_PART_RUNTIME_MAX (30 minutes = 1800 seconds)
            # This helps prevent individual test parts from running too long and enables
            # better parallel execution across pool workers.
            ConfigOption(
                "auto_part_runtime_limit",
                default=defaults.AUTO_PART_RUNTIME_MAX,
            ): Or(int, float, lambda s: s == "auto"),
            ConfigOption(
                "plan_runtime_target", default=defaults.PLAN_RUNTIME_TARGET
            ): Or(int, float, lambda s: s == "auto"),
            ConfigOption(
                "skip_strategy", default=common.SkipStrategy.noop()
            ): Use(common.SkipStrategy.from_option_or_none),
            ConfigOption("driver_info", default=False): bool,
            ConfigOption("collect_code_context", default=False): bool,
        }


class TestRunnerStatus(RunnableStatus):
    """
    Status of a
    :py:class:`TestRunner <testplan.runnable.TestRunner>` runnable object.
    """


class TestRunnerResult(RunnableResult):
    """
    Result object of a
    :py:class:`TestRunner <testplan.runnable.TestRunner>` runnable object.
    """

    def __init__(self):
        super(TestRunnerResult, self).__init__()
        self.test_results = OrderedDict()
        self.exporter_results = []
        self.report = None

    @property
    def success(self):
        """Run was successful."""
        return not self.report.failed and all(
            [
                exporter_result.success
                for exporter_result in self.exporter_results
            ]
        )


CACHED_TASK_INFO_ATTRIBUTE = "_cached_task_info"


def _attach_task_info(task_info: TaskInformation) -> Task:
    """
    Attach task information (TaskInformation) to the task object
    """
    task = task_info.target
    setattr(task, CACHED_TASK_INFO_ATTRIBUTE, task_info)
    return task


def _detach_task_info(task: Task) -> Optional[TaskInformation]:
    """
    Detach task information (TaskInformation) from the task object
    """
    task_info = getattr(task, CACHED_TASK_INFO_ATTRIBUTE)
    delattr(task, CACHED_TASK_INFO_ATTRIBUTE)
    return task_info


class TestRunner(Runnable):
    r"""
    Adds tests to test
    :py:class:`executor <testplan.runners.base.Executor>` resources
    and invoke report
    :py:class:`exporter <testplan.exporters.testing.base.Exporter>` objects
    to create the
    :py:class:`~testplan.runnable.TestRunnerResult`.

    :param name: Name of test runner.
    :type name: ``str``
    :param description: Description of test runner.
    :type description: ``str``
    :param logger_level: Logger level for stdout.
    :type logger_level: ``int``
    :param: file_log_level: Logger level for file.
    :type file_log_level: ``int``
    :param runpath: Input runpath.
    :type runpath: ``str`` or ``callable``
    :param path_cleanup: Clean previous runpath entries.
    :type path_cleanup: ``bool``
    :param all_tasks_local: Schedule all tasks in local pool
    :type all_tasks_local: ``bool``
    :param shuffle: Shuffle strategy.
    :type shuffle: ``list`` of ``str``
    :param shuffle_seed: Shuffle seed.
    :type shuffle_seed: ``float``
    :param exporters: Exporters for reports creation.
    :type exporters: ``list``
    :param stdout_style: Styling output options.
    :type stdout_style:
        :py:class:`Style <testplan.report.testing.styles.Style>`
    :param report_dir: Report directory.
    :type report_dir: ``str``
    :param xml_dir: XML output directory.
    :type xml_dir: ``str``
    :param pdf_path: PDF output path <PATH>/\*.pdf.
    :type pdf_path: ``str``
    :param json_path: JSON output path <PATH>/\*.json.
    :type json_path: ``str``
    :param pdf_style: PDF creation styling options.
    :type pdf_style: :py:class:`Style <testplan.report.testing.styles.Style>`
    :param http_url: Web url for posting test report.
    :type http_url: ``str``
    :param report_tags: Matches tests marked with any of the given tags.
    :type report_tags: ``list``
    :param report_tags_all: Match tests marked with all of the given tags.
    :type report_tags_all: ``list``
    :param merge_scheduled_parts: Merge report of scheduled MultiTest parts.
    :type merge_scheduled_parts: ``bool``
    :param browse: Open web browser to display the test report.
    :type browse: ``bool`` or ``NoneType``
    :param ui_port: Port of web server for displaying test report.
    :type ui_port: ``int`` or ``NoneType``
    :param web_server_startup_timeout: Timeout for starting web server.
    :type web_server_startup_timeout: ``int``
    :param test_filter: Tests filtering class.
    :type test_filter: Subclass of
        :py:class:`BaseFilter <testplan.testing.filtering.BaseFilter>`
    :param test_sorter: Tests sorting class.
    :type test_sorter: Subclass of
        :py:class:`BaseSorter <testplan.testing.ordering.BaseSorter>`
    :param test_lister: Tests listing class.
    :type test_lister: Subclass of
        :py:class:`BaseLister <testplan.testing.listing.BaseLister>`
    :param verbose: Enable or disable verbose mode.
    :type verbose: ``bool``
    :param debug: Enable or disable debug mode.
    :type debug: ``bool``
    :param timeout: Timeout value for test execution.
    :type timeout: ``NoneType`` or ``int`` (greater than 0).
    :param abort_wait_timeout: Timeout for test runner abort.
    :type abort_wait_timeout: ``int``
    :param interactive_handler: Handler for interactive mode execution.
    :type interactive_handler: Subclass of :py:class:
        `TestRunnerIHandler <testplan.runnable.interactive.base.TestRunnerIHandler>`
    :param extra_deps: Extra module dependencies for interactive reload, or
        paths of these modules.
    :type extra_deps: ``list`` of ``module`` or ``str``
    :param label: Label the test report with the given name, useful to
        categorize or classify similar reports .
    :type label: ``str`` or ``NoneType``
    :param runtime_data: Historical runtime data which will be used for
        Multitest auto-part and weight-based Task smart-scheduling. Contains
        execution time metrics (setup_time, execution_time, teardown_time) for
        each test, enabling intelligent partitioning and load balancing.
    :type runtime_data: ``dict``
    :param auto_part_runtime_limit: Maximum runtime allowed for each auto-partitioned
        task part (in seconds). This parameter controls how tests are automatically
        split into smaller chunks for parallel execution:
        
        - **Numeric value (int/float)**: Explicitly sets the maximum runtime per part.
          Tasks that would exceed this limit are divided into multiple parts to ensure
          balanced execution across pool workers. For example, a value of 600 means
          each part should complete within 10 minutes.
        
        - **"auto" (string)**: Automatically calculates an optimal runtime limit based on:
          
          * Historical runtime data from previous test runs
          * MultiTest setup/teardown overhead (multiplied by START_STOP_FACTOR)
          * Maximum unit test runtime
          * Constraints: result is clamped between AUTO_PART_RUNTIME_MIN and
            AUTO_PART_RUNTIME_MAX to prevent too small or too large parts
        
        **Default**: AUTO_PART_RUNTIME_MAX (1800 seconds / 30 minutes)
        
        **Purpose**: Prevents individual test parts from monopolizing pool resources
        and enables better parallel execution. Shorter limits increase parallelism
        but may add setup/teardown overhead; longer limits reduce overhead but may
        decrease parallelism.
        
        **Usage example**: Set to 600 for 10-minute parts in environments with
        frequent worker churn, or "auto" to let the system optimize based on
        historical data.
    :type auto_part_runtime_limit: ``int`` or ``float`` or literal "auto"
    :param plan_runtime_target: The testplan total runtime limitation for smart schedule
    :type plan_runtime_target: ``int`` or ``float`` or literal "auto"

    Also inherits all
    :py:class:`~testplan.common.entity.base.Runnable` options.
    """

    CONFIG = TestRunnerConfig
    STATUS = TestRunnerStatus
    RESULT = TestRunnerResult

    def __init__(self, **options):
        # TODO: check options sanity?
        super(TestRunner, self).__init__(**options)
        # uid to resource, in definition order
        self._test_metadata = []
        self._tests: MutableMapping[str, str] = OrderedDict()
        self.result.report = TestReport(
            name=self.cfg.name,
            description=self.cfg.description,
            uid=self.cfg.name,
            timeout=self.cfg.timeout,
            label=self.cfg.label,
            information=[("testplan_version", self.get_testplan_version())],
        )
        self._exporters = None
        self._web_server_thread = None
        self._file_log_handler = None
        self._configure_stdout_logger()
        # Before saving test report, recursively generate unique strings in
        # uuid4 format as report uid instead of original one. Skip this step
        # when executing unit/functional tests or running in interactive mode.
        self._reset_report_uid = not self._is_interactive_run()
        self.scheduled_modules = []  # For interactive reload
        self.remote_services: Dict[str, "RemoteService"] = {}
        self.runid_filename = uuid.uuid4().hex
        self.define_runpath()
        self._runnable_uids = set()
        self._verified_targets = {}  # target object id -> runnable uid
        self.resource_monitor_server: Optional["ResourceMonitorServer"] = None
        self.resource_monitor_server_file_path: Optional[str] = None
        self.resource_monitor_client: Optional["ResourceMonitorClient"] = None

    def __str__(self):
        return f"Testplan[{self.uid()}]"

    @staticmethod
    def get_testplan_version():
        import testplan

        return testplan.__version__

    @property
    def report(self) -> TestReport:
        """Tests report."""
        return self.result.report

    @property
    def exporters(self):
        """
        Return a list of
        :py:class:`report exporters <testplan.exporters.testing.base.Exporter>`.
        """
        if self._exporters is None:
            self._exporters = self.get_default_exporters()
            if self.cfg.exporters:
                self._exporters.extend(self.cfg.exporters)
            for exporter in self._exporters:
                if hasattr(exporter, "cfg"):
                    exporter.cfg.parent = self.cfg
                exporter.parent = self
        return self._exporters

    def get_test_metadata(self):
        return self._test_metadata

    def disable_reset_report_uid(self):
        """Do not generate unique strings in uuid4 format as report uid"""
        self._reset_report_uid = False

    def get_default_exporters(self):
        """
        Instantiate certain exporters if related cmdline argument (e.g. --pdf)
        or programmatic arguments (e.g. pdf_path) is passed but there are not
        any exporter declarations.
        """
        exporters = []
        if self.cfg.pdf_path:
            exporters.append(test_exporters.PDFExporter())
        if self.cfg.report_tags or self.cfg.report_tags_all:
            exporters.append(test_exporters.TagFilteredPDFExporter())
        if self.cfg.json_path:
            exporters.append(test_exporters.JSONExporter())
        if self.cfg.xml_dir:
            exporters.append(test_exporters.XMLExporter())
        if self.cfg.http_url:
            exporters.append(test_exporters.HTTPExporter())
        if self.cfg.dump_failed_tests:
            exporters.append(test_exporters.FailedTestsExporter())
        if self.cfg.ui_port is not None:
            exporters.append(
                test_exporters.WebServerExporter(ui_port=self.cfg.ui_port)
            )
        if (
            not self._is_interactive_run()
            and self.cfg.tracing_tests is not None
        ):
            exporters.append(test_exporters.CoveredTestsExporter())
        return exporters

    def add_environment(
        self, env: EnvironmentCreator, resource: Optional[Environments] = None
    ):
        """
        Adds an environment to the target resource holder.

        :param env: Environment creator instance.
        :type env: Subclass of
            :py:class:`~testplan.environment.EnvironmentCreator`
        :param resource: Target environments holder resource.
        :type resource: Subclass of
            :py:class:`~testplan.environment.Environments`
        :return: Environment uid.
        :rtype: ``str``
        """
        resource = (
            self.resources[resource]
            if resource
            else self.resources.environments
        )
        target = env.create(parent=self)
        env_uid = env.uid()
        resource.add(target, env_uid)
        return env_uid

    def add_resource(
        self, resource: Resource, uid: Optional[str] = None
    ) -> str:
        """
        Adds a test :py:class:`executor <testplan.runners.base.Executor>`
        resource in the test runner environment.

        :param resource: Test executor to be added.
        :param uid: Optional input resource uid. We now force its equality with
            resource's own uid.
        :return: Resource uid assigned.
        """
        resource.parent = self
        resource.cfg.parent = self.cfg
        if uid and uid != resource.uid():
            raise ValueError(
                f"Unexpected uid value ``{uid}`` received, mismatched with "
                f"Resource uid ``{resource.uid()}``"
            )
        return self.resources.add(resource, uid=uid)

    def add_exporters(self, exporters: List[Exporter]):
        """
        Add a list of
        :py:class:`report exporters <testplan.exporters.testing.base.Exporter>`
        for outputting test report.

        :param exporters: Test exporters to be added.
        :type exporters: ``list`` of :py:class:`~testplan.runners.base.Executor`
        """
        self.cfg.exporters.extend(get_exporters(exporters))

    def add_remote_service(self, remote_service: "RemoteService"):
        """
        Adds a remote service
        :py:class:`~testplan.common.remote.remote_service.RemoteService`
        object to test runner.

        :param remote_service: RemoteService object
        :param remote_service:
            :py:class:`~testplan.common.remote.remote_service.RemoteService`
        """
        name = remote_service.cfg.name
        if name in self.remote_services:
            raise ValueError(f"Remove Service [{name}] already exists")

        remote_service.parent = self
        remote_service.cfg.parent = self.cfg
        self.remote_services[name] = remote_service

    def skip_step(self, step):
        if isinstance(
            self.result.step_results.get("_start_remote_services", None),
            Exception,
        ):
            if step in (
                self._pre_exporters,
                self._invoke_exporters,
                self._post_exporters,
                self._stop_remote_services,
            ):
                return False
            return True
        return False

    def _start_remote_services(self):
        for rmt_svc in self.remote_services.values():
            try:
                rmt_svc.start()
            except Exception as e:
                msg = traceback.format_exc()
                self.logger.error(msg)
                self.report.logger.error(msg)
                self.report.status_override = Status.ERROR
                # skip the rest, set step return value
                return e

    def _stop_remote_services(self):
        es = []
        for rmt_svc in self.remote_services.values():
            try:
                rmt_svc.stop()
            except Exception as e:
                msg = traceback.format_exc()
                self.logger.error(msg)
                # NOTE: rmt svc cannot be closed before report export due to
                # NOTE: rmt ref being used during report export, it's
                # NOTE: meaningless to update report obj here
                self.report.status_override = Status.ERROR
                es.append(e)
        if es:
            if len(es) > 1:
                return ExceptionGroup(
                    "multiple remote services failed to stop", es
                )
            return es[0]

    def _clone_task_for_part(self, task_info, part_tuple):
        task_arguments = task_info.task_arguments
        task_arguments["part"] = part_tuple
        self.logger.debug(
            "Task re-created with arguments: %s",
            task_arguments,
        )

        # unfortunately it is not easy to clone a Multitest with some parameters changed
        # ideally we need just the part changed, but Multitests could not share Drivers,
        # so it could not be recreated from its configuration as then more than one
        # Multitest would own the same drivers. So here we recreating it from the task

        target = Task(**task_arguments)
        new_task_info = self._assemble_task_info(target)
        return new_task_info

    def _create_task_n_info(
        self, task_arguments, num_of_parts=None
    ) -> TaskInformation:
        self.logger.debug(
            "Task created with arguments: %s",
            task_arguments,
        )
        task = Task(**task_arguments)
        task_info = self._assemble_task_info(
            task, task_arguments, num_of_parts
        )
        return task_info

    def discover(
        self,
        path: str = ".",
        name_pattern: Union[str, Pattern] = r".*\.py$",
    ) -> List[Task]:
        """
        Discover task targets under path in the modules that matches name pattern,
        and return the created Task object.

        :param path: the root path to start a recursive walk and discover,
            default is current directory.
        :param name_pattern: a regex pattern to match the file name.
        :return: A list of Task objects
        """

        self.logger.user_info(
            "Discovering task target with file name pattern '%s' under '%s'",
            name_pattern,
            path,
        )
        regex = re.compile(name_pattern)
        discovered: List[TaskInformation] = []

        for root, dirs, files in os.walk(path or "."):
            for filename in files:
                if not regex.match(filename):
                    continue

                filepath = os.path.join(root, filename)
                module = filename.split(".")[0]

                with import_tmp_module(module, root) as mod:
                    for attr in dir(mod):
                        target = getattr(mod, attr)
                        if not is_task_target(target):
                            continue

                        self.logger.debug(
                            "Discovered task target %s::%s", filepath, attr
                        )

                        target_info: TaskTargetInformation = (
                            target.__task_target_info__
                        )  # what user specifies in @task_target

                        task_arguments = dict(
                            target=attr,
                            module=module,
                            path=root,
                            **target_info.task_kwargs,
                        )

                        if target_info.target_params:
                            for param in target_info.target_params:
                                if isinstance(param, dict):
                                    task_arguments["args"] = None
                                    task_arguments["kwargs"] = param
                                elif isinstance(param, (tuple, list)):
                                    task_arguments["args"] = param
                                    task_arguments["kwargs"] = None
                                else:
                                    raise TypeError(
                                        "task_target's parameters can only"
                                        " contain dict/tuple/list, but"
                                        f" received: {param}"
                                    )
                                discovered.append(
                                    self._create_task_n_info(
                                        deepcopy(task_arguments),
                                        target_info.multitest_parts,
                                    )
                                )
                        else:
                            discovered.append(
                                self._create_task_n_info(
                                    task_arguments, target_info.multitest_parts
                                )
                            )

        return [_attach_task_info(task_info) for task_info in discovered]

    def calculate_pool_size(self) -> None:
        """
        Calculate the right size of the pool based on the weight (runtime) of the tasks,
        so that runtime of all tasks meets the plan_runtime_target.
        """
        for executor in self.resources:
            if isinstance(executor, Pool) and executor.is_auto_size:
                pool_size = self.calculate_pool_size_by_tasks(
                    list(executor.added_items.values())
                )
                self.logger.user_info(
                    f"Set pool size to {pool_size} for {executor.cfg.name}"
                )
                executor.size = pool_size

    def calculate_pool_size_by_tasks(self, tasks: Collection[Task]) -> int:
        """
        Calculate the right size of the pool based on the weight (runtime) of the tasks,
        so that runtime of all tasks meets the plan_runtime_target.
        """
        if len(tasks) == 0:
            return 1

        _tasks = sorted(tasks, key=lambda task: task.weight, reverse=True)
        plan_runtime_target = self.cfg.plan_runtime_target

        if plan_runtime_target == "auto":
            self.logger.warning(
                "Update plan_runtime_target to %d", _tasks[0].weight
            )
            plan_runtime_target = _tasks[0].weight
        elif _tasks[0].weight > plan_runtime_target:
            for task in _tasks:
                if task.weight > plan_runtime_target:
                    self.logger.warning(
                        "%s weight %d is greater than plan_runtime_target %d",
                        task,
                        task.weight,
                        self.cfg.plan_runtime_target,
                    )
            self.logger.warning(
                "Update plan_runtime_target to %d", _tasks[0].weight
            )
            plan_runtime_target = _tasks[0].weight

        containers = [0]
        for task in _tasks:
            if task.weight:
                if min(containers) + task.weight <= plan_runtime_target:
                    containers[containers.index(min(containers))] += (
                        task.weight
                    )
                else:
                    containers.append(task.weight)
            else:
                containers.append(plan_runtime_target)
        return len(containers)

    def schedule(
        self,
        task: Optional[Task] = None,
        resource: Optional[str] = None,
        **options,
    ) -> Optional[str]:
        """
        Schedules a serializable
        :py:class:`~testplan.runners.pools.tasks.base.Task` in a task runner
        :py:class:`~testplan.runners.pools.base.Pool` executor resource.

        :param task: Input task, if it is None, a new Task will be constructed
            using the options parameter.
        :type task: :py:class:`~testplan.runners.pools.tasks.base.Task`
        :param resource: Name of the target executor, which is usually a Pool,
            default value None indicates using local executor.
        :type resource: ``str`` or ``NoneType``
        :param options: Task input options.
        :type options: ``dict``
        :return uid: Assigned uid for task.
        :rtype: ``str`` or ``NoneType``
        """

        return self.add(task or Task(**options), resource=resource)

    def schedule_all(
        self,
        path: str = ".",
        name_pattern: Union[str, Pattern] = r".*\.py$",
        resource: Optional[str] = None,
    ):
        """
        Discover task targets under path in the modules that matches name pattern,
        create task objects from them and schedule them to resource (usually pool)
        for execution.

        :param path: the root path to start a recursive walk and discover,
            default is current directory.
        :type path: ``str``
        :param name_pattern: a regex pattern to match the file name.
        :type name_pattern: ``str``
        :param resource: Name of the target executor, which is usually a Pool,
            default value None indicates using local executor.
        :type resource: ``str`` or ``NoneType``
        """

        tasks = self.discover(path=path, name_pattern=name_pattern)
        tasks = self.auto_part(tasks)
        for task in tasks:
            self.add(task, resource=resource)

    def auto_part(self, tasks: List[Task]) -> List[Task]:
        """
        Automatically partitions tasks into smaller parts based on runtime limits.
        
        This method is the entry point for the auto-partitioning feature, which
        intelligently splits long-running tests into multiple parallel parts to
        improve execution time and resource utilization.
        
        **Purpose**:
        Without partitioning, a single long-running test would monopolize a pool
        worker for its entire duration, while other workers might sit idle. By
        splitting tests into parts, we achieve better load balancing and parallelism.
        
        **Process**:
        
        1. **Check compatibility**: Auto-partitioning is disabled in interactive mode
           since test discovery and execution happen dynamically.
        
        2. **Extract task information**: Converts Task objects into TaskInformation
           for easier manipulation.
        
        3. **Adjust runtime data**: Ensures historical runtime data is available and
           properly formatted for all discovered tasks. If a task is missing from
           historical data but has a matching pattern, data is cloned from the pattern.
        
        4. **Calculate runtime limit**: Determines the auto_part_runtime_limit value:
           - If explicitly set (numeric): uses that value
           - If set to "auto": calculates based on historical data
        
        5. **Partition tasks**: For each task, calculates:
           - num_of_parts: how many parts to split into (based on runtime vs limit)
           - weight: expected execution time (for smart scheduling)
        
        6. **Return partitioned tasks**: Converts TaskInformation back to Task objects.
        
        **Example**:
        Given tasks = [MultiTest(multitest_parts="auto")] with:
        - execution_time = 2000s, setup = 100s, teardown = 50s
        - auto_part_runtime_limit = 500s
        
        Returns: [
            Task(part=(0, 5), weight=550),  # (2000/5) + 100 + 50
            Task(part=(1, 5), weight=550),
            Task(part=(2, 5), weight=550),
            Task(part=(3, 5), weight=550),
            Task(part=(4, 5), weight=550),
        ]
        
        Each part runs ~400s of test execution + 150s overhead = 550s total,
        fitting within the 500s limit (accounting for scheduling overhead).
        
        :param tasks: List of tasks to potentially partition
        :type tasks: List[Task]
        :return: List of tasks, possibly expanded with partitioned versions
        :rtype: List[Task]
        """
        partitioned: List[TaskInformation] = []

        # Auto-partitioning requires static test discovery; not compatible with interactive mode
        if self._is_interactive_run():
            self.logger.debug("Auto part is not supported in interactive mode")
            return tasks

        # Convert Task objects to TaskInformation for easier processing
        discovered: List[TaskInformation] = [
            _detach_task_info(task) for task in tasks
        ]
        runtime_data = self.cfg.runtime_data or {}
        # Ensure all discovered tasks have runtime data (clone from patterns if needed)
        self._adjust_runtime_data(discovered, runtime_data)
        # Update config with adjusted runtime data for consistency
        # Also updates testcase_count from historical data to current run count
        self.cfg.set_local("runtime_data", runtime_data)

        # Determine the runtime limit for auto-partitioning
        # This is either explicitly configured or automatically calculated
        auto_part_runtime_limit = self._calculate_part_runtime(discovered)
        # For each task, calculate optimal number of parts and execution weights
        for task_info in discovered:
            partitioned.extend(
                self._calculate_parts_and_weights(
                    task_info, auto_part_runtime_limit
                )
            )

        # Convert TaskInformation back to Task objects and return
        return [_attach_task_info(task_info) for task_info in partitioned]

    def _adjust_runtime_data(
        self, discovered: List[TaskInformation], runtime_data: dict
    ):
        """
        Adjust the runtime data to ensure that all discovered tasks have their
        runtime data available. If a task's UID is not found in the runtime data,
        it will be added with default values.
        """
        for task_info in discovered:
            uid = task_info.uid
            time_info = runtime_data.get(uid, None)
            if time_info and isinstance(
                task_info.materialized_test, MultiTest
            ):
                if prev_case_count := time_info.get("testcase_count", 0):
                    # XXX: cache dry_run result somewhere?
                    # NOTE: get_metadata won't work here since filters not applied
                    if (
                        curr_case_count
                        := task_info.materialized_test.dry_run().report.counter[
                            "total"
                        ]
                    ):
                        # XXX: lb defined, ub?
                        adjusted_exec_time = time_info["execution_time"] * max(
                            curr_case_count / prev_case_count,
                            MULTITEST_EXEC_TIME_ADJUST_FACTOR_LB,
                        )
                        self.logger.user_info(
                            "%s: adjust estimated total execution time %.2f -> %.2f "
                            "(prev total testcase number: %d, curr total testcase number: %d)",
                            uid,
                            time_info["execution_time"],
                            adjusted_exec_time,
                            prev_case_count,
                            curr_case_count,
                        )
                        time_info["execution_time"] = adjusted_exec_time
                        time_info["testcase_count"] = curr_case_count

    def _calculate_part_runtime(
        self, discovered: List[TaskInformation]
    ) -> float:
        """
        Calculate the optimal runtime limit for auto-partitioned task parts.
        
        This method determines how long each auto-partitioned task part should be
        allowed to run. The calculation strategy depends on the configured value:
        
        1. **Explicit limit**: If auto_part_runtime_limit is set to a numeric value,
           returns that value directly without calculation.
        
        2. **Auto mode**: If set to "auto", calculates an optimal limit based on:
           - Historical runtime data from previous test runs
           - The maximum setup+teardown time across all MultiTests
           - The maximum total runtime of unit tests
           
        **Algorithm for "auto" mode**:
        
        a) If no runtime_data is available, returns AUTO_PART_RUNTIME_MAX as a safe default.
        
        b) For each discovered task, extracts timing information:
           - For MultiTest: tracks setup_time + teardown_time (start/stop overhead)
           - For unit tests: tracks setup_time + execution_time + teardown_time (total runtime)
        
        c) Calculates initial limit as:
           max_multitest_start_stop * START_STOP_FACTOR (default: 3x)
           This ensures parts run long enough to amortize setup/teardown costs.
        
        d) Applies constraints:
           - Lower bound: AUTO_PART_RUNTIME_MIN (8 minutes) - prevents too many small parts
           - Upper bound: AUTO_PART_RUNTIME_MAX (30 minutes) - prevents parts from running too long
        
        e) Takes the maximum of calculated limit and max unit test runtime,
           ensuring unit tests can complete within the limit.
        
        :param discovered: List of task information objects containing test metadata
        :type discovered: List[TaskInformation]
        :return: Calculated runtime limit in seconds
        :rtype: float
        """
        # If user explicitly set a numeric limit, use it directly
        if self.cfg.auto_part_runtime_limit != "auto":
            return self.cfg.auto_part_runtime_limit

        runtime_data = self.cfg.runtime_data or {}
        # Without historical data, we cannot make informed decisions
        if not runtime_data:
            self.logger.warning(
                "Cannot derive auto_part_runtime_limit without runtime data, "
                "set to default %s",
                defaults.AUTO_PART_RUNTIME_MAX,
            )
            return defaults.AUTO_PART_RUNTIME_MAX

        # Track the maximum start/stop time for MultiTests (setup + teardown overhead)
        max_mt_start_stop = 0  # multitest
        # Track the maximum total runtime for unit tests (all phases combined)
        max_ut_runtime = 0  # unit test

        for task_info in discovered:
            uid = task_info.uid
            time_info = runtime_data.get(uid, None)

            if time_info:
                if isinstance(task_info.materialized_test, MultiTest):
                    # For MultiTest, we care about setup+teardown overhead since
                    # execution time is what gets partitioned
                    max_mt_start_stop = max(
                        max_mt_start_stop,
                        time_info["setup_time"] + time_info["teardown_time"],
                    )
                else:
                    # For unit tests (PyTest, GTest, etc.), track total runtime
                    # since they cannot be partitioned
                    max_ut_runtime = (
                        time_info["setup_time"]
                        + time_info["execution_time"]
                        + time_info["teardown_time"]
                    )

            else:
                # If any task lacks runtime data, we cannot reliably calculate
                # the optimal limit, so fall back to the default maximum
                self.logger.warning(
                    "Cannot find runtime data for %s, "
                    "set auto_part_runtime_limit to default %d",
                    uid,
                    defaults.AUTO_PART_RUNTIME_MAX,
                )
                return defaults.AUTO_PART_RUNTIME_MAX

        # Calculate initial limit based on MultiTest overhead
        # Multiply by START_STOP_FACTOR (3x) to ensure parts run long enough
        # to amortize the fixed setup/teardown cost
        auto_part_runtime_limit = (
            max_mt_start_stop * defaults.START_STOP_FACTOR
        )
        # Apply lower and upper bounds to prevent extreme values
        # Min: 8 minutes (avoid too many small parts with high overhead ratio)
        # Max: 30 minutes (avoid parts monopolizing resources for too long)
        auto_part_runtime_limit = min(
            max(auto_part_runtime_limit, defaults.AUTO_PART_RUNTIME_MIN),
            defaults.AUTO_PART_RUNTIME_MAX,
        )
        # Ensure the limit is at least as large as the longest unit test
        # (since unit tests cannot be split, they must fit within the limit)
        auto_part_runtime_limit = math.ceil(
            max(auto_part_runtime_limit, max_ut_runtime)
        )

        self.logger.user_info(
            "Set auto_part_runtime_limit to %s", auto_part_runtime_limit
        )
        return auto_part_runtime_limit

    def _calculate_parts_and_weights(
        self, task_info: TaskInformation, auto_part_runtime_limit: float
    ):
        """
        Calculate the number of parts to split a task into and assign execution weights.
        
        This method determines how to partition a single task into multiple parts for
        parallel execution, based on the auto_part_runtime_limit. It also assigns
        execution weights to parts for smart scheduling.
        
        **Partitioning Logic**:
        
        For MultiTest tasks with multitest_parts specified:
        
        1. **Explicit num_of_parts**: If a numeric value is provided via @task_target,
           uses that value directly.
        
        2. **Auto num_of_parts**: If set to "auto", calculates based on:
           - Divides execution_time by available time per part
           - Available time = auto_part_runtime_limit - setup_time - teardown_time
           - This ensures each part fits within the runtime limit including overhead
        
        3. **Safety constraints**:
           - Minimum parts = 1 (even for very fast tests)
           - Maximum parts = 2 × (execution_time / auto_part_runtime_limit)
             This cap ensures setup/teardown overhead stays below 50% of total runtime
        
        **Weight Calculation**:
        
        Weight represents expected execution time in seconds, used by smart schedulers
        to balance load across pool workers:
        
        - For partitioned tasks:
          weight = (execution_time / num_of_parts) + setup_time + teardown_time
          Each part gets equal share of execution time plus full overhead
        
        - For non-partitioned tasks:
          weight = execution_time + setup_time + teardown_time
          Total runtime of the entire task
        
        **Example**:
        Given a MultiTest with:
        - execution_time = 1000s, setup_time = 100s, teardown_time = 50s
        - auto_part_runtime_limit = 400s
        
        Available time per part = 400 - 100 - 50 = 250s
        num_of_parts = ceil(1000 / 250) = 4 parts
        weight per part = (1000 / 4) + 100 + 50 = 400s
        
        :param task_info: Information about the task to partition
        :type task_info: TaskInformation
        :param auto_part_runtime_limit: Maximum runtime allowed per part (seconds)
        :type auto_part_runtime_limit: float
        :return: List of task information objects (one per part)
        :rtype: List[TaskInformation]
        """
        # Extract num_of_parts from @task_target decorator (e.g., multitest_parts=3 or "auto")
        num_of_parts = (
            task_info.num_of_parts
        )  # @task_target(multitest_parts=...)
        uid = task_info.uid
        runtime_data: dict = self.cfg.runtime_data or {}
        time_info: Optional[dict] = runtime_data.get(uid, None)

        partitioned: List[TaskInformation] = []

        # Only partition if num_of_parts is specified (not None)
        if num_of_parts:
            # Partitioning is only supported for MultiTest
            if not isinstance(task_info.materialized_test, MultiTest):
                raise TypeError(
                    "multitest_parts specified in @task_target,"
                    " but the Runnable is not a MultiTest"
                )

            # If num_of_parts is "auto", calculate optimal number of parts
            if num_of_parts == "auto":
                if not time_info:
                    # Without historical data, cannot calculate; default to 1 part
                    self.logger.warning(
                        "%s parts is auto but cannot find it in runtime-data",
                        uid,
                    )
                    num_of_parts = 1
                else:
                    # Calculate upper bound (cap) to prevent excessive partitioning
                    # Cap ensures setup/teardown overhead stays below 50% of total runtime
                    # Example: If execution_time=1000s and limit=400s, cap=5 parts
                    #   With 5 parts: each part runs ~200s + overhead
                    #   5 × overhead should be ≤ 50% of total time
                    cap = math.ceil(
                        time_info["execution_time"]
                        / auto_part_runtime_limit
                        * 2
                    )
                    # Prepare formula string for error logging
                    formula = f"""
            num_of_parts = math.ceil(
                time_info["execution_time"] {time_info["execution_time"]}
                / (
                    self.cfg.auto_part_runtime_limit {auto_part_runtime_limit}
                    - time_info["setup_time"] {time_info["setup_time"]}
                    - time_info["teardown_time"] {time_info["teardown_time"]}
                )
            )
"""
                    try:
                        # Core calculation: divide execution time by available time per part
                        # Available time = limit - fixed overhead (setup + teardown)
                        # This ensures: part_execution_time + overhead ≤ limit
                        num_of_parts = math.ceil(
                            time_info["execution_time"]
                            / (
                                auto_part_runtime_limit
                                - time_info["setup_time"]
                                - time_info["teardown_time"]
                            )
                        )
                    except ZeroDivisionError:
                        # Can occur if limit ≤ setup_time + teardown_time
                        # Means overhead alone exceeds the limit; cannot partition
                        self.logger.error(
                            f"ZeroDivisionError occurred when calculating num_of_parts for {uid}, set to 1. {formula}"
                        )
                        num_of_parts = 1

                    # Validate calculated num_of_parts and apply constraints
                    if num_of_parts < 1:
                        # Should not happen with ceil(), but guard against edge cases
                        self.logger.error(
                            f"Calculated num_of_parts for {uid} is {num_of_parts}, set to 1. {formula}"
                        )
                        num_of_parts = 1

                    if num_of_parts > cap:
                        # Apply cap to prevent overhead from dominating total runtime
                        self.logger.error(
                            f"Calculated num_of_parts for {uid} is {num_of_parts} > cap {cap}, set to {cap}. {formula}"
                        )
                        num_of_parts = cap

            # At this point, num_of_parts is a valid integer (user-specified or auto-derived)
            # Calculate execution weight for smart scheduling
            task_arguments = task_info.task_arguments
            if "weight" not in task_arguments:
                # Weight = expected execution time for this part/task
                # For partitioned tasks: equal share of execution + full overhead
                # For non-partitioned: total execution + overhead
                task_arguments["weight"] = (
                    math.ceil(
                        (time_info["execution_time"] / num_of_parts)
                        + time_info["setup_time"]
                        + time_info["teardown_time"]
                    )
                    if time_info
                    # Without historical data, use runtime limit as weight estimate
                    else int(auto_part_runtime_limit)
                )
            self.logger.user_info(
                "%s: parts=%d, weight=%d",
                uid,
                num_of_parts,
                task_arguments["weight"],
            )
            # Create task info objects for each part
            if num_of_parts == 1:
                # No actual partitioning needed, but still set weight
                task_info.target.weight = task_arguments["weight"]
                partitioned.append(task_info)
            else:
                # Create separate task for each part
                # Each part will execute a subset of test cases
                for i in range(num_of_parts):
                    part_tuple = (i, num_of_parts)
                    new_task_info = self._clone_task_for_part(
                        task_info, part_tuple
                    )
                    partitioned.append(new_task_info)

        else:
            # Task does not request partitioning; just calculate weight if available
            if time_info and not task_info.target.weight:
                # For non-partitioned tasks, weight is total expected runtime
                task_info.target.weight = math.ceil(
                    time_info["execution_time"]
                    + time_info["setup_time"]
                    + time_info["teardown_time"]
                )
            if task_info.target.weight:
                self.logger.user_info(
                    "%s: weight=%d", uid, task_info.target.weight
                )
            partitioned.append(task_info)

        return partitioned

    def add(
        self,
        target: Union[Test, Task, Callable],
        resource: Optional[str] = None,
    ) -> Optional[str]:
        """
        Adds a :py:class:`runnable <testplan.common.entity.base.Runnable>`
        test entity, or a :py:class:`~testplan.runners.pools.tasks.base.Task`,
        or a callable that returns a test entity to a
        :py:class:`~testplan.runners.base.Executor` resource.

        :param target: Test target.
        :type target: :py:class:`~testplan.common.entity.base.Runnable` or
            :py:class:`~testplan.runners.pools.tasks.base.Task` or ``callable``
        :param resource: Name of the target executor, which is usually a Pool,
            default value None indicates using local executor.
        :type resource: ``str`` or ``NoneType``
        :return: Assigned uid for test.
        :rtype: ``str`` or ```NoneType``
        """

        # Get the real test entity and verify if it should be added
        task_info = self._assemble_task_info(target)
        self._verify_task_info(task_info)
        uid = task_info.uid

        # let see if it is filtered
        if not self._should_task_running(task_info):
            return None

        # "--list" option always means not executing tests
        lister: Lister = self.cfg.test_lister
        if lister is not None and not lister.metadata_based:
            self.cfg.test_lister.log_test_info(task_info.materialized_test)
            return None

        if resource is None or self._is_interactive_run():
            # use local runner for interactive
            resource = self.resources.first()
            # just enqueue the materialized test
            target = task_info.materialized_test
        else:
            target = task_info.target

        if self._is_interactive_run():
            self._register_task_for_interactive(task_info)

        self._register_task(
            resource, target, uid, task_info.materialized_test.get_metadata()
        )
        return uid

    def _is_interactive_run(self):
        return self.cfg.interactive_port is not None

    def _register_task(self, resource, target, uid, metadata):
        self._tests[uid] = resource
        self._test_metadata.append(metadata)
        self.resources[resource].add(target, uid)

    def _assemble_task_info(
        self,
        target: TestTask,
        task_arguments: Optional[dict] = None,
        num_of_parts: Optional[int] = None,
    ) -> TaskInformation:
        if isinstance(target, Task):
            if hasattr(target, CACHED_TASK_INFO_ATTRIBUTE):
                task_info = _detach_task_info(target)
                return task_info
            else:
                materialized_test = target.materialize()
        elif isinstance(target, Test):
            materialized_test = target
        elif callable(target):
            materialized_test = target()
        else:
            raise TypeError(
                "Unrecognized test target of type {}".format(type(target))
            )

        # TODO: include executor in ancestor chain?
        if isinstance(materialized_test, Runnable):
            materialized_test.parent = self
            materialized_test.cfg.parent = self.cfg

        uid = materialized_test.uid()

        # Reset the task uid which will be used for test result transport in
        # a pool executor, it makes logging or debugging easier.

        # TODO: This mutating target should we do a copy?
        if isinstance(target, Task):
            target._uid = uid

        return TaskInformation(
            target, materialized_test, uid, task_arguments, num_of_parts
        )

    def _register_task_for_interactive(self, task_info: TaskInformation):
        target = task_info.target
        if isinstance(target, Task) and isinstance(target._target, str):
            self.scheduled_modules.append(
                (
                    target._module or target._target.rsplit(".", 1)[0],
                    os.path.abspath(target._path),
                )
            )

    def _verify_task_info(self, task_info: TaskInformation) -> None:
        uid = task_info.uid
        if uid in self._tests:
            raise ValueError(
                '{} with uid "{}" already added.'.format(self._tests[uid], uid)
            )

        if uid in self._runnable_uids:
            raise RuntimeError(
                f"Runnable with uid {uid} has already been verified"
            )
        else:
            #  TODO: this should be part of the add
            self._runnable_uids.add(uid)

    def _should_task_running(self, task_info: TaskInformation) -> bool:
        should_run = True
        if type(self.cfg.test_filter) is not filtering.Filter:
            test = task_info.materialized_test
            should_run = test.should_run()
            self.logger.debug(
                "Should run %s? %s",
                test.name,
                "Yes" if should_run else "No",
            )

        return should_run

    def make_runpath_dirs(self):
        """
        Creates runpath related directories.
        """
        if self._runpath is None:
            raise RuntimeError(
                "{} runpath cannot be None".format(self.__class__.__name__)
            )

        self.logger.user_info(
            "Testplan[%s] has runpath: %s and pid %s",
            self.cfg.name,
            self._runpath,
            os.getpid(),
        )

        self._scratch = os.path.join(self._runpath, "scratch")

        if self.cfg.path_cleanup is False:
            makedirs(self._runpath)
            makedirs(self._scratch)
        else:
            makeemptydirs(self._runpath)
            makeemptydirs(self._scratch)

        with open(
            os.path.join(self._runpath, self.runid_filename), "wb"
        ) as fp:
            pass

        if self.cfg.resource_monitor:
            self.resource_monitor_server_file_path = os.path.join(
                self.scratch, "resource_monitor"
            )
            makedirs(self.resource_monitor_server_file_path)

        if not os.environ.get("MPLCONFIGDIR"):
            os.environ["MPLCONFIGDIR"] = os.path.join(
                self._runpath, "matplotlib"
            )

    def _start_resource_monitor(self):
        """Start resource monitor server and client"""
        from testplan.monitor.resource import (
            ResourceMonitorClient,
            ResourceMonitorServer,
        )

        if self.cfg.resource_monitor:
            self.resource_monitor_server = ResourceMonitorServer(
                self.resource_monitor_server_file_path,
                detailed=self.cfg.logger_level == logger.DEBUG,
            )
            self.resource_monitor_server.start()
            self.resource_monitor_client = ResourceMonitorClient(
                self.resource_monitor_server.address, is_local=True
            )
            self.resource_monitor_client.start()

    def _stop_resource_monitor(self):
        """Stop resource monitor server and client"""
        if self.resource_monitor_client:
            self.resource_monitor_client.stop()
            self.resource_monitor_client = None
        if self.resource_monitor_server:
            self.resource_monitor_server.stop()
            self.resource_monitor_server = None

    def add_pre_resource_steps(self):
        """Runnable steps to be executed before resources started."""
        self._add_step(self.timer.start, "run")
        super(TestRunner, self).add_pre_resource_steps()
        self._add_step(self._start_remote_services)
        self._add_step(self.make_runpath_dirs)
        self._add_step(self._configure_file_logger)
        self._add_step(self.calculate_pool_size)
        self._add_step(self._start_resource_monitor)

    def add_main_batch_steps(self):
        """Runnable steps to be executed while resources are running."""
        self._add_step(self._wait_ongoing)

    def add_post_resource_steps(self):
        """Runnable steps to be executed after resources stopped."""
        self._add_step(self._create_result)
        self._add_step(self._log_test_status)
        self._add_step(self.timer.end, "run")  # needs to happen before export
        self._add_step(self._pre_exporters)
        self._add_step(self._invoke_exporters)
        self._add_step(self._post_exporters)
        self._add_step(self._stop_remote_services)
        super(TestRunner, self).add_post_resource_steps()
        self._add_step(self._stop_resource_monitor)

    def _collect_timeout_info(self):
        threads, processes = self._get_process_info(recursive=True)
        self._timeout_info = {"threads": [], "processes": []}
        for thread in threads:
            self._timeout_info["threads"].append(
                os.linesep.join(
                    [thread.name]
                    + format_stack(sys._current_frames()[thread.ident])
                )
            )

        for process in processes:
            command = " ".join(process.cmdline()) or process
            parent_pid = getattr(process, "ppid", lambda: None)()
            self._timeout_info["processes"].append(
                f"Pid: {process.pid}, Parent pid: {parent_pid}, {command}"
            )

    def _wait_ongoing(self):
        # TODO: if a pool fails to initialize we could reschedule the tasks.
        if self.resources.start_exceptions:
            for resource, exception in self.resources.start_exceptions.items():
                self.logger.critical(
                    "Aborting %s due to start exception", resource
                )
                resource.abort()

        _start_ts = time.time()

        while self.active:
            if self.cfg.timeout and time.time() - _start_ts > self.cfg.timeout:
                msg = f"Timeout: Aborting execution after {self.cfg.timeout} seconds"
                self.result.report.logger.error(msg)
                self.logger.error(msg)
                self._collect_timeout_info()

                # Abort resources e.g pools
                for dep in self.abort_dependencies():
                    self._abort_entity(dep)
                break

            pending_work = False
            for resource in self.resources:
                # Check if any resource has pending work.
                # Maybe print periodically the pending work of resource.
                pending_work = resource.pending_work() or pending_work

                # Poll the resource's health - if it has unexpectedly died
                # then abort the entire test to avoid hanging.
                if not resource.is_alive:
                    self.result.report.status_override = Status.ERROR
                    self.logger.critical(
                        "Aborting %s - %s unexpectedly died", self, resource
                    )
                    self.abort()

            if pending_work is False:
                break
            time.sleep(self.cfg.active_loop_sleep)

    def _post_run_checks(self, start_threads, start_procs):
        super()._post_run_checks(start_threads, start_procs)
        self._close_file_logger()

    def _create_result(self):
        """Fetch task result from executors and create a full test result."""
        step_result = True
        test_results = self.result.test_results
        plan_report = self.result.report
        test_rep_lookup = {}

        for uid, resource in self._tests.items():
            if not isinstance(self.resources[resource], Executor):
                continue

            resource_result = self.resources[resource].results.get(uid)
            # Tasks may not been executed (i.e. timeout), although the thread
            # will wait for a buffer period until the follow up work finishes.
            # But for insurance we assume that still some uids are missing.
            if not resource_result:
                continue
            elif isinstance(resource_result, TaskResult):
                if resource_result.result is None:
                    test_results[uid] = result_for_failed_task(resource_result)
                else:
                    test_results[uid] = resource_result.result
            else:
                test_results[uid] = resource_result

            run, report = test_results[uid].run, test_results[uid].report

            if report.part:
                if (
                    report.category != ReportCategories.TASK_RERUN
                    and self.cfg.merge_scheduled_parts
                ):
                    # Save the report temporarily and later will merge it
                    test_rep_lookup.setdefault(
                        report.definition_name, []
                    ).append((test_results[uid].run, report))
                    if report.definition_name not in plan_report.entry_uids:
                        # Create a placeholder for merging sibling reports

                        # here `report` must be an empty MultiTest report since
                        # parting is mt-only feature, directly creating an original-
                        # compatible mt report would reduce mt materialize overhead

                        # while currently the only parting strategy is case-level
                        # round-robin, more complicated parting strategy could make
                        # it hard to obtain the defined mt/ts/tc order, since then
                        # ref report from dry_run will become necessary

                        report = TestGroupReport(
                            name=report.definition_name,
                            description=report.description,
                            category=ReportCategories.MULTITEST,
                            tags=report.tags,
                        )
                    else:
                        continue  # Wait all sibling reports collected

            plan_report.append(report)
            step_result = step_result and run is True  # boolean or exception

        step_result = self._merge_reports(test_rep_lookup) and step_result

        if hasattr(self, "_timeout_info"):
            msg = f"Testplan timed out after {self.cfg.timeout} seconds"
            timeout_entry = TestGroupReport(
                name="Testplan timeout",
                description=msg,
                category=ReportCategories.SYNTHESIZED,
                # status_override=Status.ERROR,
            )
            timeout_case = TestCaseReport(
                name="Testplan timeout",
                description=msg,
                status_override=Status.ERROR,
            )

            log_result = Result()
            log_result.log(
                message=f"".join(
                    f"{log['created'].strftime('%Y-%m-%d %H:%M:%S')} {log['levelname']} {log['message']}\n"
                    for log in self.report.flattened_logs
                ),
                description="Logs from testplan",
            )
            log_result.log(
                message=os.linesep.join(self._timeout_info["threads"]),
                description="Stack trace from threads",
            )
            log_result.log(
                message=os.linesep.join(self._timeout_info["processes"])
                if len(self._timeout_info["processes"])
                else "No child processes",
                description="Running child processes",
            )

            timeout_case.extend(log_result.serialized_entries)
            timeout_entry.append(timeout_case)
            plan_report.append(timeout_entry)

        # Reset UIDs of the test report and all of its children in UUID4 format
        if self._reset_report_uid:
            plan_report.reset_uid()

        return step_result

    def _merge_reports(
        self, test_report_lookup: Dict[str, List[Tuple[bool, Any]]]
    ):
        """
        Merge report of MultiTest parts into test runner report.
        Return True if all parts are found and can be successfully merged.

        Format of test_report_lookup:
        {
            'report_uid_1': [
                (True, report_1_part_1), (True, report_1_part_2), ...
            ],
            'report_uid_2': [
                (True, report_2_part_1), (False, report_2_part_2), ...
            ],
            ...
        }
        """
        merge_result = True

        for uid, result in test_report_lookup.items():
            placeholder_report: TestGroupReport = (
                self.result.report.get_by_uid(uid)
            )
            num_of_parts = 0
            part_indexes = set()
            merged = False

            # XXX: should we continue merging on exception raised?
            with placeholder_report.logged_exceptions():
                disassembled = []
                for run, report in result:
                    report: TestGroupReport
                    if num_of_parts and num_of_parts != report.part[1]:
                        raise ValueError(
                            "Cannot merge parts for child report with"
                            " `uid`: {uid}, invalid parameter of part"
                            " provided.".format(uid=uid)
                        )
                    elif report.part[0] in part_indexes:
                        raise ValueError(
                            "Cannot merge parts for child report with"
                            " `uid`: {uid}, duplicate MultiTest parts"
                            " had been scheduled.".format(uid=uid)
                        )
                    else:
                        part_indexes.add(report.part[0])
                        num_of_parts = report.part[1]

                    if run:
                        if isinstance(run, Exception):
                            raise run
                        else:
                            report.annotate_part_num()
                            flatten = list(report.pre_order_disassemble())
                            disassembled.append(collate_for_merging(flatten))
                    else:
                        raise MergeError(
                            f"While merging parts of report `uid`: {uid}, "
                            f"part {report.part[0]} didn't run. Merge of this part was skipped"
                        )
                for it in zip_longest(*disassembled, fillvalue=()):
                    for es in it:
                        for e in es:
                            if not e.parent_uids:
                                # specially handle mt entry
                                placeholder_report.merge(e)
                            else:
                                placeholder_report.graft_entry(
                                    e, copy(e.parent_uids[1:])
                                )
                placeholder_report.build_index(recursive=True)
                merged = True

            # If fail to merge sibling reports, clear the placeholder report
            # but keep error logs, sibling reports will be appended at the end.
            if not merged:
                placeholder_report.entries = []
                placeholder_report._index = {}
                placeholder_report.status_override = Status.ERROR
                for _, report in result:
                    report.name = (
                        common.TEST_PART_PATTERN_FORMAT_STRING.format(
                            report.name, report.part[0], report.part[1]
                        )
                    )
                    report.uid = strings.uuid4()  # considered as error report
                    self.result.report.append(report)

            merge_result = (
                merge_result and placeholder_report.status != Status.ERROR
            )

        return merge_result

    def uid(self):
        """Entity uid."""
        return self.cfg.name

    def _log_test_status(self):
        if not self.result.report.entries:
            self.logger.warning(
                "No tests were run - check your filter patterns."
            )
        else:
            self.logger.log_test_status(
                self.cfg.name, self.result.report.status
            )

    def _pre_exporters(self):
        # Apply report filter if one exists
        if self.cfg.reporting_exclude_filter is not None:
            self.result.report = self.cfg.reporting_exclude_filter(
                self.result.report
            )

        # Attach resource monitor data
        if self.resource_monitor_server:
            self.report.resource_meta_path = (
                self.resource_monitor_server.dump()
            )

    def _invoke_exporters(self) -> None:
        if self.result.report.is_empty():  # skip empty report
            return

        if hasattr(self.result.report, "bubble_up_attachments"):
            self.result.report.bubble_up_attachments()

        export_context = ExportContext()
        for exporter in self.exporters:
            if isinstance(exporter, test_exporters.Exporter):
                run_exporter(
                    exporter=exporter,
                    source=self.result.report,
                    export_context=export_context,
                )
            else:
                raise NotImplementedError(
                    "Exporter logic not implemented for: {}".format(
                        type(exporter)
                    )
                )

        self.result.exporter_results = export_context.results

    def _post_exporters(self):
        # View report in web browser if "--browse" specified
        report_urls = []
        report_opened = False

        if self.result.report.is_empty():  # skip empty report
            self.logger.warning("Empty report, nothing to be exported!")
            return

        for result in self.result.exporter_results:
            report_url = getattr(result.exporter, "report_url", None)
            if report_url:
                report_urls.append(report_url)
                web_server_thread = getattr(
                    result.exporter, "web_server_thread", None
                )
                if web_server_thread:
                    # Keep an eye on this thread from `WebServerExporter`
                    # which will be stopped on Testplan abort
                    self._web_server_thread = web_server_thread
                    # Give priority to open report from local server
                    if self.cfg.browse and not report_opened:
                        webbrowser.open(report_url)
                        report_opened = True
                    # Stuck here waiting for web server to terminate
                    web_server_thread.join()

        if self.cfg.browse and not report_opened:
            if len(report_urls) > 0:
                for report_url in report_urls:
                    webbrowser.open(report_url)
            else:
                self.logger.warning(
                    "No reports opened, could not find "
                    "an exported result to browse"
                )

    def discard_pending_tasks(
        self,
        exec_selector: SExpr,
        report_status: Status = Status.INCOMPLETE,
        report_reason: str = "",
    ):
        for k, v in self.resources.items():
            if isinstance(v, Executor) and apply_single(exec_selector, k):
                v.discard_pending_tasks(report_status, report_reason)

    def abort_dependencies(self):
        """
        Yield all dependencies to be aborted before self abort.
        """
        if self._ihandler is not None:
            yield self._ihandler
        yield from super(TestRunner, self).abort_dependencies()

    def aborting(self):
        """Stop the web server if it is running."""
        if self._web_server_thread is not None:
            self._web_server_thread.stop()
        # XXX: to be refactored after aborting logic implemented for rmt svcs
        self._stop_remote_services()
        self._stop_resource_monitor()
        self._close_file_logger()

    def _configure_stdout_logger(self):
        """Configure the stdout logger by setting the required level."""
        logger.STDOUT_HANDLER.setLevel(self.cfg.logger_level)

    def _configure_file_logger(self):
        """
        Configure the file logger to the specified log levels. A log file
        will be created under the runpath (so runpath must be created before
        this method is called).
        """
        if self.runpath is None:
            raise RuntimeError(
                "Need to set up runpath before configuring logger"
            )

        if self.cfg.file_log_level is None:
            self.logger.debug("Not enabling file logging")
        else:
            self._file_log_handler = logger.configure_file_logger(
                self.cfg.file_log_level, self.runpath
            )

    def _close_file_logger(self):
        """
        Closes the file logger, releasing all file handles. This is necessary to
        avoid permissions errors on Windows.
        """
        if self._file_log_handler is not None:
            self._file_log_handler.flush()
            self._file_log_handler.close()
            logger.TESTPLAN_LOGGER.removeHandler(self._file_log_handler)
            self._file_log_handler = None

    def _run_batch_steps(self):
        if not self._tests:
            self.logger.warning("No tests were added, skipping execution!")
            self.status.change(self.STATUS.RUNNING)
            self.status.change(self.STATUS.FINISHED)
        else:
            super()._run_batch_steps()

    def run(self):
        """
        Executes the defined steps and populates the result object.
        """
        if self.cfg.test_lister:
            self.result.run = True
            return self.result

        return super().run()
