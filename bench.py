import csv
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from itertools import product
from pathlib import Path


def hardware(system):
    if system == "Darwin":
        return subprocess.check_output(
            ["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string", "hw.memsize"], text=True
        ).splitlines()

    cpu = platform.machine()
    for line in Path("/proc/cpuinfo").read_text().splitlines():
        key, _, value = line.partition(":")
        if key.strip() in ("model name", "Hardware"):
            cpu = value.strip()
            break
    return cpu, os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")


def run_sample(binary, n):
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace") as log:
        start = time.perf_counter_ns()
        try:
            process = subprocess.Popen([binary, "-n", str(n)], stdout=log, stderr=subprocess.STDOUT)
        except OSError as error:
            return None, time.perf_counter_ns() - start, None, str(error)

        with process:
            _, status, usage = os.wait4(process.pid, 0)
            elapsed = time.perf_counter_ns() - start
            # wait4 has already reaped the child.
            process.returncode = os.waitstatus_to_exitcode(status)
        log.seek(0)
        return process.returncode, elapsed, usage.ru_maxrss, log.read()


def measurements(log):
    stage = ""
    rows = []
    for line in log.splitlines(keepends=True):
        if not line.endswith("\n"):
            continue
        fields = line.rstrip("\n").split(",")
        if fields[0] == "stage" and len(fields) == 3:
            _, phase, level = fields
            stage = f"{phase} level {level}"
        elif fields[0] == "measurement" and len(fields) == 6:
            _, phase, level, *values = fields
            for metric, value in zip(("duration_ns", "proof_count", "proof_bytes"), map(int, values)):
                if value:
                    rows.append((phase, level, metric, value))
    return stage, rows


def run_benchmark(output, binary, runs, sizes):
    system = platform.system()
    if system not in ("Darwin", "Linux"):
        sys.exit("Peak RSS collection requires macOS or Linux.")
    rss_scale = 1024 if system == "Linux" else 1
    cpu, memory = hardware(system)
    with (output / "config.txt").open("a", encoding="utf-8") as config:
        print(f"\nsizes={sizes}\nruns={runs}\nos={platform.platform()}", file=config)
        print(f"cpu={cpu}\narchitecture={platform.machine()}\nlogical_cpus={os.cpu_count()}", file=config)
        print(f"memory_bytes={memory}\nGOMAXPROCS={os.environ.get('GOMAXPROCS')}\nconcurrent_samples=1", file=config)

    print(f"Writing results to {output}", flush=True)
    groups = defaultdict(list)
    failed = False
    with (output / "samples.csv").open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(("n", "repetition", "exit_code", "last_stage", "phase", "level", "metric", "value"))
        for n, repetition in product(sizes, range(1, runs + 1)):
            print(f"N={n}, repetition {repetition}/{runs}", flush=True)
            code, elapsed, rss, log = run_sample(binary, n)
            stage, rows = measurements(log)
            rows.append(("process", "", "wall_time_ns", elapsed))
            if rss is not None:
                rows.append(("process", "", "peak_rss_bytes", rss * rss_scale))
            for phase, level, metric, value in rows:
                writer.writerow((n, repetition, code, stage, phase, level, metric, value))
                if code == 0:
                    groups[n, phase, level, metric].append(value)
            file.flush()
            if code != 0:
                (output / "failure.log").write_text(log, encoding="utf-8")
                print(f"Failed N={n}, repetition {repetition}, last stage {stage or 'none'}.")
                failed = True
                break

    with (output / "summary.csv").open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(("n", "phase", "level", "metric", "sample_count", "mean", "median", "iqr"))
        for key, values in sorted(groups.items()):
            iqr = 0
            if len(values) > 1:
                q1, _, q3 = statistics.quantiles(values, method="inclusive")
                iqr = q3 - q1
            writer.writerow((*key, len(values), statistics.mean(values), statistics.median(values), iqr))
    return int(failed)


def main():
    backend, runs, *sizes = sys.argv[1:]
    runs = int(runs)
    sizes = list(map(int, sizes))
    if runs < 1 or not sizes or len(sizes) != len(set(sizes)):
        sys.exit("Set RUNS to a positive integer and N to distinct sizes.")

    with tempfile.TemporaryDirectory() as build:
        binary = Path(build) / backend
        subprocess.run(["go", "build", "-o", binary, "."], cwd=backend, check=True)

        results = Path("bench-results")
        results.mkdir(exist_ok=True)
        output = Path(tempfile.mkdtemp(dir=results, prefix=f"{backend}."))
        with (output / "config.txt").open("w", encoding="utf-8") as config:
            subprocess.run(["go", "version", "-m", binary], stdout=config, check=True)
        return run_benchmark(output, binary, runs, sizes)


if __name__ == "__main__":
    raise SystemExit(main())
