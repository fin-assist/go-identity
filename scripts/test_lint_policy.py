"""The forbidigo rules in .golangci.yml reject every way to reach process-wide state.

The pinned golangci-lint (version from the Makefile) runs with the repository's
.golangci.yml on a generated probe module: one line per forbidden identifier, which must
be reported, chains and an aliased import, blank imports rejected by depguard, and the
allowed forms (constructors, adapters, methods on injected values), which must not. All
probe dependencies are pinned. The probe runs for linux and windows, so the platform
packages are checked too. Static checks pin analyze-types, the exclusions and the
linter version shared with ci.yml.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

try:
    import yaml
except ImportError as error:  # a missing parser must fail the checks, never skip them
    raise ImportError("PyYAML is required by scripts/test_lint_policy.py: "
                      "install python3-yaml or `pip install pyyaml`") from error


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / ".golangci.yml"
LINT_VERSION = re.search(r"^GOLANGCI_LINT_VERSION := (\S+)$", (ROOT / "Makefile").read_text(), re.M)[1]
GO_MOD = (ROOT / "go.mod").read_text()


def module_version(module):
    match = re.search(r"^\s*" + re.escape(module) + r" (v\S+)", GO_MOD, re.M)
    if match is None:
        raise AssertionError(f"{module} is not in go.mod; pin it in PINNED instead")
    return match[1]


# The probe is hermetic: every module it compiles is pinned, so an upstream release cannot break CI.
# Versions present in go.mod follow it exactly (Renovate updates them there). Renovate does not read the
# hand-pinned constants below: they are raised by hand in a reviewed PR, when the libraries or services move to a
# new otel/klog/automaxprocs/automemlimit release, or when the probe needs an API that only a newer release has.
# A go.mod module raised by Renovate may require a newer release of a hand-pinned one (grpc -> otel): go mod tidy
# then raises it, and the probe accepts any version not lower than the hand pin, so a bot-only PR stays green.
GO_VERSION = re.search(r"^go (\S+)$", GO_MOD, re.M)[1]
FROM_GO_MOD = {
    module: module_version(module)
    for module in ["github.com/prometheus/client_golang", "google.golang.org/grpc", "golang.org/x/sys"]
}
# go-identity does not depend on these: the probe pins the template's releases by hand (minimum versions).
HAND_PINNED = {
    "go.opentelemetry.io/otel": "v1.44.0",
    "go.opentelemetry.io/otel/log": "v0.20.0",  # the release paired with otel v1.44.0
    "go.opentelemetry.io/otel/metric": "v1.44.0",
    "go.opentelemetry.io/otel/trace": "v1.44.0",
    "k8s.io/klog": "v1.0.0",
    "k8s.io/klog/v2": "v2.130.1",
    "go.uber.org/automaxprocs": "v1.6.0",
    "github.com/KimMachineGun/automemlimit": "v1.0.1",
}
PINNED = {**FROM_GO_MOD, **HAND_PINNED}

SEMVER = re.compile(r"^v(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def semver_key(version):
    """Orders Go module versions by semver precedence (build metadata ignored)."""
    match = SEMVER.match(version)
    if match is None:
        raise ValueError(f"not a semantic version: {version}")
    release = tuple(int(part) for part in match.group(1, 2, 3))
    pre = match[4]
    if pre is None:
        return release, (1,)  # a release sorts after every pre-release of the same version
    identifiers = tuple((0, int(part), "") if part.isdigit() else (1, 0, part) for part in pre.split("."))
    return release, (0, identifiers)


def pin_holds(module, pinned, resolved):
    """An exact match for a version from go.mod; for a hand pin, any version not lower than it."""
    if module in FROM_GO_MOD:
        return resolved == pinned
    return semver_key(resolved) >= semver_key(pinned)


def resolved_version(go_mod, module):
    match = re.search(r"^\s*" + re.escape(module) + r" (v\S+)", go_mod, re.M)
    return match[1] if match else None

PROMETHEUS = "github.com/prometheus/client_golang/prometheus"
# import path -> identifiers that must be reported; every one is referenced as a value.
FORBIDDEN = {
    "fmt": ["Print", "Printf", "Println"],
    "log/slog": ["Default", "SetDefault", "SetLogLoggerLevel", "Debug", "DebugContext", "Info", "InfoContext",
                 "Warn", "WarnContext", "Error", "ErrorContext", "Log", "LogAttrs"],
    "log": ["Print", "Printf", "Println", "Fatal", "Fatalf", "Fatalln", "Panic", "Panicf", "Panicln",
            "Default", "Writer", "SetOutput", "SetFlags", "SetPrefix", "Flags", "Prefix", "Output"],
    "google.golang.org/grpc/grpclog": ["Info", "Infof", "Infoln", "InfoDepth", "Warning", "Warningf",
                                       "Warningln", "WarningDepth", "Error", "Errorf", "Errorln", "ErrorDepth",
                                       "Fatal", "Fatalf", "Fatalln", "FatalDepth", "Print", "Printf", "Println",
                                       "V", "Component", "SetLogger", "SetLoggerV2"],
    PROMETHEUS: ["MustRegister", "Register", "Unregister", "DefaultRegisterer", "DefaultGatherer"],
    PROMETHEUS + "/promauto": ["NewCounter", "NewCounterVec", "NewCounterFunc", "NewGauge", "NewGaugeVec",
                               "NewGaugeFunc", "NewHistogram", "NewHistogramVec", "NewSummary",
                               "NewSummaryVec", "NewUntypedFunc"],
    PROMETHEUS + "/promhttp": ["Handler"],
    "net/http": ["DefaultClient", "DefaultTransport", "DefaultServeMux", "Handle", "HandleFunc", "Get", "Head",
                 "Post", "PostForm", "ListenAndServe", "ListenAndServeTLS"],
    "go.opentelemetry.io/otel": ["GetTracerProvider", "SetTracerProvider", "GetMeterProvider",
                                 "SetMeterProvider", "GetTextMapPropagator", "SetTextMapPropagator",
                                 "SetErrorHandler", "GetErrorHandler", "SetLogger", "Tracer", "Meter",
                                 "Handle"],
    "go.opentelemetry.io/otel/log/global": ["GetLoggerProvider", "SetLoggerProvider", "Logger"],
    "os/signal": ["Notify", "NotifyContext", "Ignore", "Reset", "Stop"],
    "os": ["Getenv", "LookupEnv", "Environ", "ExpandEnv", "Setenv", "Unsetenv", "Clearenv", "Args",
           "UserHomeDir", "UserConfigDir", "UserCacheDir", "Stdout", "Stderr", "Stdin", "TempDir",
           "CreateTemp", "MkdirTemp", "Chdir"],
    "syscall": ["Getenv", "Environ", "Setenv", "Unsetenv", "Clearenv", "Chdir"],
    "flag": ["Arg", "Args", "Bool", "BoolFunc", "BoolVar", "CommandLine", "Duration", "DurationVar", "Float64",
             "Float64Var", "Func", "Int", "Int64", "Int64Var", "IntVar", "Lookup", "NArg", "NFlag", "Parse",
             "Parsed", "PrintDefaults", "Set", "String", "StringVar", "TextVar", "Uint", "Uint64", "Uint64Var",
             "UintVar", "Usage", "Var", "Visit", "VisitAll"],
    "runtime/debug": ["SetCrashOutput", "SetGCPercent", "SetMaxStack", "SetMaxThreads", "SetMemoryLimit",
                      "SetPanicOnFault", "SetTraceback"],
    "runtime": ["GOMAXPROCS", "SetDefaultGOMAXPROCS"],
}
PLATFORM = {
    "unix": {"golang.org/x/sys/unix": ["Getenv", "Environ", "Setenv", "Unsetenv", "Clearenv", "Chdir", "Fchdir"],
             "syscall": ["Fchdir"]},
    "windows": {"golang.org/x/sys/windows": ["Getenv", "Environ", "Setenv", "Unsetenv", "Clearenv",
                                             "GetEnvironmentVariable", "SetEnvironmentVariable", "Chdir",
                                             "SetCurrentDirectory"],
                "syscall": ["GetEnvironmentVariable", "SetEnvironmentVariable", "GetEnvironmentStrings",
                            "SetCurrentDirectory"]},
}

# Chains and an aliased import: each marked line must be reported by its first identifier.
CHAINS = '''package probe

import (
	"context"
	stdlog "log"
	"log/slog"
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"
)

// Chains reaches process-wide state through a chain, an alias or a method.
func Chains(ctx context.Context, c prometheus.Collector, req *http.Request, f *os.File) {
	prometheus.DefaultRegisterer.MustRegister(c) // want
	stdlog.Default().Printf("x")                 // want
	slog.Default().InfoContext(ctx, "x")         // want
	_, _ = http.DefaultClient.Do(req)            // want
	_ = otel.GetTracerProvider().Tracer("x")     // want
	stdlog.Printf("x")                           // want
	_ = f.Chdir()                                // want
}
'''

# Imported even blank, these change process-wide state in init: depguard rejects each import line.
BLANK = '''package probe

import (
	_ "expvar"                                 // want
	_ "github.com/KimMachineGun/automemlimit"  // want
	_ "github.com/golang/glog"                 // want
	_ "go.uber.org/automaxprocs"               // want
	_ "golang.org/x/net/trace"                 // want
	_ "google.golang.org/grpc/grpclog/glogger" // want
	_ "k8s.io/klog"                            // want
	_ "k8s.io/klog/v2"                         // want
	_ "net/http/pprof"                         // want
)
'''


def marked(text):
    return {number for number, line in enumerate(text.splitlines(), start=1) if line.endswith("// want")}

ALLOWED = '''package probe

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/grpclog"
)

// GRPCLogger is an adapter a library may export; the service installs it with SetLoggerV2.
func GRPCLogger(w io.Writer) grpclog.LoggerV2 {
	var logger grpclog.LoggerV2 = grpclog.NewLoggerV2(w, w, w)
	_ = grpclog.NewLoggerV2WithVerbosity(w, w, w, 1)
	var _ grpclog.DepthLoggerV2
	return logger
}

// Allowed uses injected values only; none of these lines may be reported.
func Allowed(ctx context.Context, l *slog.Logger, reg prometheus.Registerer, c prometheus.Collector,
	client *http.Client, w io.Writer, tp trace.TracerProvider, mp metric.MeterProvider) {
	_ = tp.Tracer("x")
	_ = mp.Meter("x")
	set := flag.NewFlagSet("library", flag.ContinueOnError)
	set.SetOutput(w)
	_ = set.String("name", "", "usage")
	_ = set.Parse(nil)
	_, _ = flag.UnquoteUsage(set.Lookup("name"))
	_, _ = os.OpenFile(filepath.Join("dir", "file"), os.O_RDWR|os.O_CREATE, 0o600)
	_ = os.Mkdir(filepath.Join("dir", "sub"), 0o700)
	_, _ = debug.ReadBuildInfo()
	_ = debug.Stack()
	_ = runtime.NumCPU()
	_ = runtime.GOMAXPROCS(0) //nolint:forbidigo // read-only default of a pool size the service may override
	file, _ := os.Open("x")
	_ = file.Name()
	_, _ = file.ReadDir(1)
	l.InfoContext(ctx, "x")
	l.Info("x")
	slog.New(slog.NewTextHandler(w, nil)).ErrorContext(ctx, "x", slog.String("k", "v"))
	std := log.New(w, "", 0)
	std.SetOutput(w)
	std.Printf("x")
	reg.MustRegister(c)
	r := prometheus.NewRegistry()
	r.MustRegister(c)
	_ = prometheus.NewCounter(prometheus.CounterOpts{Name: "x"})
	promauto.With(reg).NewCounter(prometheus.CounterOpts{Name: "y"})
	promauto.With(r).NewGaugeVec(prometheus.GaugeOpts{Name: "z"}, nil)
	h := promhttp.HandlerFor(r, promhttp.HandlerOpts{})
	_ = promhttp.InstrumentMetricHandler(reg, h)
	mux := http.NewServeMux()
	mux.Handle("/", h)
	_, _ = client.Get("http://example.invalid")
	_, _ = os.ReadFile("x")
	_ = os.Expand("$A", func(string) string { return "" })
	_ = fmt.Sprintf("x")
	_, _ = fmt.Fprintf(w, "x")
}
'''


def module_path(import_path):
    return import_path.rsplit("/", 1)[-1]


def forbidden_file(imports, build="", name="Forbidden"):
    lines = ([build, ""] if build else []) + ["package probe", "", "import ("]
    lines += [f'\t"{path}"' for path in imports]
    lines += [")", "", f"// {name} references every forbidden identifier on its own line.", f"func {name}() {{"]
    expected = set()
    for path, names in imports.items():
        for name in names:  # every name of the family, one per line
            lines.append(f"\t_ = {module_path(path)}.{name}")
            expected.add(len(lines))
    if not build:
        for builtin in ["print", "println"]:
            lines.append(f'\t{builtin}("x")')
            expected.add(len(lines))
    lines.append("}")
    return "\n".join(lines) + "\n", expected


def lint(root, tool, goos):
    command = [str(tool), "run",
               "--allow-parallel-runners", "--enable-only", "forbidigo,depguard", "--max-issues-per-linter", "0",
               "--max-same-issues", "0", "--output.json.path", "stdout", "--show-stats=false", "./..."]
    result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=600,
                            env=dict(os.environ, GOTOOLCHAIN="auto", GOOS=goos, GOFLAGS="-mod=mod"))
    report = json.loads(result.stdout.strip().splitlines()[-1]) if result.stdout.strip() else None
    if report is None:
        raise AssertionError(f"golangci-lint produced no report:\n{result.stderr}")
    return report.get("Issues") or [], result


class ConfigTests(unittest.TestCase):
    def test_forbidigo_matches_types_and_excludes_only_tests_and_pgtest(self):
        config = yaml.safe_load(CONFIG.read_text())
        self.assertIs(config["linters"]["settings"]["forbidigo"]["analyze-types"], True)
        excluded = sorted(rule["path"] for rule in config["linters"]["exclusions"]["rules"]
                          if "forbidigo" in rule.get("linters", []))
        self.assertEqual(excluded, sorted([r"_test\.go", "internal/pgtest/"]))

    def test_probe_uses_the_linter_version_of_ci(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        self.assertEqual(workflow["env"]["GOLANGCI_LINT_VERSION"], LINT_VERSION)


class PinTests(unittest.TestCase):
    def test_semver_order(self):
        ordered = ["v1.0.0-alpha", "v1.0.0-alpha.1", "v1.0.0-alpha.beta", "v1.0.0-beta.2", "v1.0.0-beta.11",
                   "v1.0.0-rc.1", "v1.0.0", "v1.0.1", "v1.10.0", "v2.0.0"]
        keys = [semver_key(version) for version in ordered]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(len(set(keys)), len(keys))
        self.assertEqual(semver_key("v1.2.3+meta"), semver_key("v1.2.3"))
        with self.assertRaises(ValueError):
            semver_key("1.2.3")

    def test_hand_pin_is_a_minimum(self):
        module, pinned = "go.opentelemetry.io/otel", HAND_PINNED["go.opentelemetry.io/otel"]
        self.assertTrue(pin_holds(module, "v1.44.0", "v1.44.0"))
        self.assertTrue(pin_holds(module, "v1.44.0", "v1.45.0"))
        self.assertTrue(pin_holds(module, "v1.44.0", "v2.0.0"))
        self.assertFalse(pin_holds(module, "v1.44.0", "v1.43.9"))
        self.assertFalse(pin_holds(module, "v1.44.0", "v1.44.0-rc.1"))
        self.assertTrue(pin_holds(module, "v1.44.0", "v1.45.0-rc.1"))
        self.assertEqual(pinned, "v1.44.0")

    def test_go_mod_version_is_exact(self):
        module = "google.golang.org/grpc"
        pinned = FROM_GO_MOD[module]
        self.assertTrue(pin_holds(module, pinned, pinned))
        major, minor, patch = semver_key(pinned)[0]
        self.assertFalse(pin_holds(module, pinned, f"v{major}.{minor + 1}.0"))
        self.assertFalse(pin_holds(module, pinned, f"v{major}.{minor}.{patch}-rc.1"))

    def test_every_hand_pin_is_absent_from_go_mod(self):
        for module in HAND_PINNED:
            self.assertIsNone(resolved_version(GO_MOD, module), module)

    def test_resolved_version(self):
        text = "require (\n\tgo.opentelemetry.io/otel v1.45.0\n\tgo.opentelemetry.io/otel/log v0.21.0 // indirect\n)\n"
        self.assertEqual(resolved_version(text, "go.opentelemetry.io/otel"), "v1.45.0")
        self.assertEqual(resolved_version(text, "go.opentelemetry.io/otel/log"), "v0.21.0")
        self.assertIsNone(resolved_version(text, "k8s.io/klog"))


class ProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        root = cls.root = Path(cls.directory.name)
        shutil.copyfile(CONFIG, root / ".golangci.yml")
        requires = "".join(f"\t{module} {version}\n" for module, version in sorted(PINNED.items()))
        (root / "go.mod").write_text(f"module example.com/probe\n\ngo {GO_VERSION}\n\nrequire (\n{requires})\n")
        common, cls.expected = forbidden_file(FORBIDDEN)
        (root / "forbidden.go").write_text(common)
        cls.platform = {}
        for goos, imports in PLATFORM.items():
            text, lines = forbidden_file(imports, f"//go:build {goos}", "Forbidden" + goos.title())
            (root / f"forbidden_{goos}.go").write_text(text)
            cls.platform[goos] = lines
        (root / "allowed.go").write_text(ALLOWED)
        (root / "chains.go").write_text(CHAINS)
        (root / "blank.go").write_text(BLANK)
        # Exclusions: tests and exactly internal/pgtest are exempt; a similar path is not.
        reference = 'package {pkg}\n\nimport "os"\n\nfunc Env() string {{ return os.Getenv("X") }}\n'
        (root / "probe_test.go").write_text(reference.format(pkg="probe").replace("Env()", "testEnv()"))
        for folder in ["internal/pgtest", "internal/pgtestx"]:
            (root / folder).mkdir(parents=True)
            (root / folder / "env.go").write_text(reference.format(pkg=folder.rsplit("/", 1)[-1]))
        # Build the pinned linter once for the host; GOOS then selects only the analysed platform.
        install = subprocess.run(["go", "install", f"github.com/golangci/golangci-lint/v2/cmd/golangci-lint@{LINT_VERSION}"],
                                 capture_output=True, text=True, timeout=900,
                                 env=dict(os.environ, GOTOOLCHAIN="auto", GOBIN=str(root / "bin")))
        if install.returncode != 0:
            raise AssertionError(install.stderr)
        cls.tool = root / "bin" / "golangci-lint"
        tidy = subprocess.run(["go", "mod", "tidy"], cwd=root, capture_output=True, text=True, timeout=600,
                              env=dict(os.environ, GOTOOLCHAIN="auto"))
        if tidy.returncode != 0:
            raise AssertionError(tidy.stderr)
        resolved = (root / "go.mod").read_text()
        for module, version in PINNED.items():
            found = resolved_version(resolved, module)
            if found is None or not pin_holds(module, version, found):
                raise AssertionError(f"tidy moved the pinned {module} off {version} (got {found}):\n{resolved}")

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def check(self, goos):
        issues, result = lint(self.root, self.tool, goos)
        others = [issue for issue in issues if issue["FromLinter"] not in ("forbidigo", "depguard")]
        self.assertEqual(others, [], result.stderr)
        reported = {(issue["Pos"]["Filename"], issue["Pos"]["Line"]) for issue in issues}
        expected = {("forbidden.go", line) for line in self.expected}
        expected |= {(f"forbidden_{goos_}.go", line)
                     for goos_, lines in self.platform.items()
                     if goos_ == ("windows" if goos == "windows" else "unix") for line in lines}
        expected.add(("internal/pgtestx/env.go", 5))
        expected |= {("chains.go", line) for line in marked(CHAINS)}
        expected |= {("blank.go", line) for line in marked(BLANK)}
        self.assertEqual(sorted(reported - expected), [], "reported outside the forbidden lines")
        self.assertEqual(sorted(expected - reported), [], "forbidden lines not reported")

    def test_linux(self):
        self.check("linux")

    def test_windows(self):
        self.check("windows")


if __name__ == "__main__":
    unittest.main()
