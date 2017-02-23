import dis
import os
import shutil
import re
import subprocess
import sys
import types
import tempfile
import unittest

from enum import Enum, unique
from test.support import findfile, run_unittest


def abspath(filename):
    return os.path.abspath(findfile(filename, subdir="dtracedata"))


def normalize_trace_output(output):
    """Normalize DTrace output for comparison.

    DTrace keeps a per-CPU buffer, and when showing the fired probes, buffers
    are concatenated. So if the operating system moves our thread around, the
    straight result can be "non-causal". So we add timestamps to the probe
    firing, sort by that field, then strip it from the output"""

    # When compiling with '--with-pydebug', strip '[# refs]' debug output.
    output = re.sub(r"\[[0-9]+ refs\]", "", output)
    try:
        result = [
            row.split("\t")
            for row in output.splitlines()
            if row and not row.startswith('#')
        ]
        result.sort(key=lambda row: int(row[0]))
        result = [row[1] for row in result]
        return "\n".join(result)
    except (IndexError, ValueError):
        raise AssertionError(
            "tracer produced unparseable output:\n{}".format(output)
        )


class TraceBackend:
    EXTENSION = None
    COMMAND = None
    COMMAND_ARGS = []

    def run_case(self, name, optimize_python=None):
        actual_output = normalize_trace_output(self.trace_python(
            script_file=abspath(name + self.EXTENSION),
            python_file=abspath(name + ".py"),
            optimize_python=optimize_python))

        with open(abspath(name + self.EXTENSION + ".expected")) as f:
            expected_output = f.read().rstrip()

        return (expected_output, actual_output)

    def generate_trace_command(self, script_file, subcommand=None):
        command = self.COMMAND + [script_file]
        if subcommand:
            command += ["-c", subcommand]
        return command

    def trace(self, script_file, subcommand=None):
        command = self.generate_trace_command(script_file, subcommand)
        stdout, _ = subprocess.Popen(command,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT,
                                     universal_newlines=True).communicate()
        return stdout

    def trace_python(self, script_file, python_file, optimize_python=None):
        python_flags = []
        if optimize_python:
            python_flags.extend(["-O"] * optimize_python)
        subcommand = " ".join([sys.executable] + python_flags + [python_file])
        return self.trace(script_file, subcommand)

    def assert_usable(self):
        try:
            output = self.trace(abspath("assert_usable" + self.EXTENSION))
            output = output.strip()
        except (FileNotFoundError, NotADirectoryError, PermissionError) as fnfe:
            output = str(fnfe)
        if output != "probe: success":
            raise unittest.SkipTest(
                "{}(1) failed: {}".format(self.COMMAND[0], output)
            )


class DTraceBackend(TraceBackend):
    EXTENSION = ".d"
    COMMAND = ["dtrace", "-q", "-s"]

class SystemTapBackend(TraceBackend):
    EXTENSION = ".stp"
    COMMAND = ["stap", "-g"]

@unique
class LTTNG_CMD(Enum):
    CREATE = 1
    ENABLE_USPACE_EVENTS = 2
    START = 3
    STOP = 4
    VIEW = 5
    DESTROY = 6
    VERSION = 7

class LTTngUSTBackend():
    EXTENSION = ".lttng"
    trace_path = None
    session_name = None
    lttng_commands={
            LTTNG_CMD.CREATE:['lttng', 'create'],
            LTTNG_CMD.ENABLE_USPACE_EVENTS:['lttng', 'enable-event', '--userspace'],
            LTTNG_CMD.START:['lttng', 'start'],
            LTTNG_CMD.STOP:['lttng', 'stop'],
            LTTNG_CMD.VIEW:['lttng', 'view'],
            LTTNG_CMD.DESTROY:['lttng', 'destroy'],
            LTTNG_CMD.VERSION:['lttng', '--version']
            }

    def exec_lttng_command(self, cmd, session_cmd, option=None):
        try:
            cmd_args = list(self.lttng_commands[cmd])
        except KeyError:
            raise AssertionError('LTTng command not found.')

        if session_cmd is not None:
            cmd_args.append(session_cmd)

        if option is not None:
            cmd_args += option

        stdout, _ = subprocess.Popen(cmd_args,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT,
                                     universal_newlines=True).communicate()
        return stdout

    def setup_tracing_session(self, test_case_name):
        # Create a temporary file for the tracing session
        self.trace_path = tempfile.mkdtemp()
        trace_folder =  '--output={}'.format(self.trace_path)
        self.session_name = 'python_tests_{}'.format(os.getpid())
        _ = self.exec_lttng_command(LTTNG_CMD.CREATE, self.session_name, [trace_folder])

        # Format the event filter depending on the testcase
        event_filter = None
        if test_case_name in 'call_stack':
            event_filter = ['python:function_*', '--filter=co_filename == "{}"'.format(abspath('call_stack.py'))]
        elif test_case_name in 'gc':
            event_filter = ['python:function_*,python:gc_*']
        elif test_case_name in 'line':
           event_filter = ['python:function_*,python:line', '--filter=co_filename == "{}"'.format(abspath('line.py'))]
        enable_event_session = '--session={}'.format(self.session_name)
        _ = self.exec_lttng_command(LTTNG_CMD.ENABLE_USPACE_EVENTS, enable_event_session, event_filter)
        _ = self.exec_lttng_command(LTTNG_CMD.START, self.session_name)

    def get_trace_output(self):
        _ = self.exec_lttng_command(LTTNG_CMD.STOP, self.session_name)
        return self.exec_lttng_command(LTTNG_CMD.VIEW, self.session_name)

    def teardown_tracing_session(self):
        _ = self.exec_lttng_command(LTTNG_CMD.DESTROY, self.session_name)
        shutil.rmtree(self.trace_path)

    def run_case(self, name, optimize_python=None):
        actual_output = self.trace_python(
            python_file=abspath(name + ".py"),
            test_case_name = name,
            optimize_python=optimize_python)
        with open(abspath(name + self.EXTENSION + ".expected")) as f:
            expected_output = f.read().rstrip()

        return (expected_output,  actual_output)

    def run_python(self, python_file, optimize_python=None):
        python_flags = []
        if optimize_python:
            python_flags.extend(["-O"] * optimize_python)
        subcommand = [sys.executable] + python_flags + [python_file]

        _, _ = subprocess.Popen(subcommand,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT,
                                     universal_newlines=True).communicate()

    def sanitize_trace(self, output, test_case_name):
        # Filter out any trace event that occured before and after main
        start_pattern = '.*python:function__entry.*co_name = "(start|test_line)".*'
        end_pattern = '.*python:function__return.*co_name = "(start|test_line)".*'
        copy = False
        cleaned_output = [];
        for line in output.split('\n'):
            if re.search(start_pattern, line):
                copy = True
            elif copy is True and re.search(end_pattern, line):
                #Copy the last line
                cleaned_output += [line]
                copy = False

            if copy:
                cleaned_output += [line]

        # Depending on the testcase, define regular expression to capture the
        # tracepoint payload
        payload_regex = {
                'gc' : r'\[.*\] \(.*\).*(?P<tp_name>python:gc_.*):.*{ (?P<gc_arg>(collected|generation) = [0-9]+) }',
                'call_stack' : r'\[.*\] \(.*\).*(?P<tp_name>python:function_.*):.*{ co_filename = "(?P<filename>.*)", co_name = "(?P<obj_name>.*)", line_no = (?P<line_no>.*) }',
                'line' : r'\[.*\] \(.*\).*(?P<tp_name>python:line):.*{ co_filename = "(?P<filename>.*)", co_name = "(?P<obj_name>.*)", line_no = (?P<line_no>.*) }'
                }
        out = []
        for line in cleaned_output:
            match = re.search(payload_regex[test_case_name], line)
            if match is not None:
                out += [match.groupdict()]

        for evt in out :
            if 'filename' in evt:
                evt['filename']=os.path.basename(evt['filename'])

        return out

    def trace_python(self,  python_file, test_case_name, optimize_python=None):
        self.setup_tracing_session(test_case_name)
        self.run_python(python_file, optimize_python=optimize_python)
        output = self.get_trace_output()
        self.teardown_tracing_session()
        clean_output = self.sanitize_trace(output, test_case_name=test_case_name)

        out =  '\n'.join([' '.join(e.values()) for e in clean_output])
        return out

    def assert_usable(self):
        out = None
        try:
            out = self.exec_lttng_command(LTTNG_CMD.VERSION, session_cmd=None)
        except (FileNotFoundError, PermissionError) as fnfe:
            out = str(fnfe)
        if 'lttng (LTTng Trace Control)' not in out:
            raise unittest.SkipTest(
                "{} failed: {}".format(" ".join(self.lttng_commands[LTTNG_CMD.VERSION]), out)
            )

class TraceTests(unittest.TestCase):
    # unittest.TestCase options
    maxDiff = None

    # TraceTests options
    backend = None
    optimize_python = 0

    @classmethod
    def setUpClass(self):
        self.backend.assert_usable()

    def run_case(self, name):
        expected_output, actual_output = self.backend.run_case(
            name, optimize_python=self.optimize_python)

        self.assertEqual(actual_output, expected_output)

    def test_function_entry_return(self):
        self.run_case("call_stack")

    def test_verify_call_opcodes(self):
        """Ensure our call stack test hits all function call opcodes"""

        opcodes = set(["CALL_FUNCTION", "CALL_FUNCTION_EX", "CALL_FUNCTION_KW"])

        with open(abspath("call_stack.py")) as f:
            code_string = f.read()

        def get_function_instructions(funcname):
            # Recompile with appropriate optimization setting
            code = compile(source=code_string,
                           filename="<string>",
                           mode="exec",
                           optimize=self.optimize_python)

            for c in code.co_consts:
                if isinstance(c, types.CodeType) and c.co_name == funcname:
                    return dis.get_instructions(c)
            return []

        for instruction in get_function_instructions('start'):
            opcodes.discard(instruction.opname)

        self.assertEqual(set(), opcodes)

    def test_gc(self):
        self.run_case("gc")

    def test_line(self):
        self.run_case("line")


class DTraceNormalTests(TraceTests):
    backend = DTraceBackend()
    optimize_python = 0


class DTraceOptimizedTests(TraceTests):
    backend = DTraceBackend()
    optimize_python = 2


class SystemTapNormalTests(TraceTests):
    backend = SystemTapBackend()
    optimize_python = 0


class SystemTapOptimizedTests(TraceTests):
    backend = SystemTapBackend()
    optimize_python = 2

class LTTngUSTNormalTests(TraceTests):
    backend = LTTngUSTBackend()
    optimize_python = 0

class LTTngUSTOptimizedTests(TraceTests):
    backend = LTTngUSTBackend()
    optimize_python = 2

def test_main():
    run_unittest(DTraceNormalTests, DTraceOptimizedTests, SystemTapNormalTests,
                 SystemTapOptimizedTests, LTTngUSTNormalTests,
                 LTTngUSTOptimizedTests)

if __name__ == '__main__':
    test_main()
