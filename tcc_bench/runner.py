from typing import List, Tuple
import os
import sys
import json
import subprocess
from tqdm import tqdm


GENERATION_FLAGS: List[Tuple[str, List[str]]] = [
    (
        "gcc_tcc",
        [
            "--cc=gcc",
            "--extra-cflags=-O2",
        ],
    ),
    (
        "gcc_tcc_ubsan",
        [
            "--cc=gcc",
            "--extra-cflags=-O2 -fsanitize=undefined",
            "--extra-ldflags=-fsanitize=undefined",
        ],
    ),
    (
        "gcc_tcc_nostack",
        [
            "--cc=gcc",
            "--extra-cflags=-O2 -fno-stack-protector",
        ],
    ),
    (
        "clang_tcc",
        [
            "--cc=clang",
            "--extra-cflags=-O2",
        ],
    ),
    (
        "clang_tcc_ubsan",
        [
            "--cc=clang",
            "--extra-cflags=-O2 -fsanitize=undefined",
            "--extra-ldflags=-fsanitize=undefined",
        ],
    ),
    (
        "clang_tcc_ubsan_min",
        [
            "--cc=clang",
            "--extra-cflags=-O2 -fsanitize=undefined -fsanitize-minimal-runtime",
            "--extra-ldflags=-fsanitize=undefined -fsanitize-minimal-runtime",
        ],
    ),
    (
        "clang_tcc_asan",
        [
            "--cc=clang",
            "--extra-cflags=-O2 -fsanitize=address",
            "--extra-ldflags=-fsanitize=address",
        ],
    ),
    (
        "clang_tcc_ubsan_asan",
        [
            "--cc=clang",
            "--extra-cflags=-O2 -fsanitize=undefined,address",
            "--extra-ldflags=-fsanitize=undefined,address",
        ],
    ),
    (
        "clang_tcc_asan_bounds",
        [
            "--cc=clang",
            "--extra-cflags=-O2 -fsanitize=address,bounds,array-bounds",
            "--extra-ldflags=-fsanitize=address,bounds,array-bounds",
        ],
    ),
    (
        "clang_tcc_ubsan_asan_bounds",
        [
            "--cc=clang",
            "--extra-cflags=-O2 -fsanitize=undefined,address,bounds,array-bounds",
            "--extra-ldflags=-fsanitize=undefined,address,bounds,array-bounds",
        ],
    ),
    (
        "clang_tcc_bounds",
        [
            "--cc=clang",
            "--extra-cflags=-O2 -fsanitize=bounds,array-bounds",
            "--extra-ldflags=-fsanitize=bounds,array-bounds",
        ],
    ),
    (
        "clang_tcc_safestack",
        [
            "--cc=clang",
            "--extra-cflags=-O2 -fsanitize=safe-stack",
            "--extra-ldflags=-fsanitize=safe-stack",
        ],
    ),
    (
        "gcc_fortify_0",
        [
            "--cc=gcc",
            "--extra-cflags=-O2 -D_FORTIFY_SOURCE=0",
        ],
    ),
    (
        "gcc_fortify_1",
        [
            "--cc=gcc",
            "--extra-cflags=-O2 -D_FORTIFY_SOURCE=1",
        ],
    ),
    (
        "gcc_fortify_2",
        [
            "--cc=gcc",
            "--extra-cflags=-O2 -D_FORTIFY_SOURCE=2",
        ],
    ),
    (
        "gcc_fortify_3",
        [
            "--cc=gcc",
            "--extra-cflags=-O2 -D_FORTIFY_SOURCE=3",
        ],
    ),
]

REPORT_DIR: str = "reports"
GENERATION_TARGET_DIR: str = "generated"
GENERATION_SOURCE_DIR: str = "tinycc"

TEST_C_FILE: str = "testfiles/speedbench.c"
INCLUDE_PATH: str = "/home/livian/tcc_bench/tinycc/include"


def exec_in_context(
    cwd: str, binary: str, args: List[str], context: List[str] = [], stderr=None
):
    """Function that executes a binary in a given context

    Args:
        binary (str): The binary to execute
        args (List[str]): Arguments passed to the executable
        context (List[str]): The context is comprised of a command that is prepended to the
            call to popen, allowing for easier instrumentation of the binary

    """
    owd = os.getcwd()
    os.chdir(cwd)

    try:
        output = subprocess.check_output(
            context + [binary] + args, text=True, stderr=stderr
        )
    except subprocess.CalledProcessError as e:
        print(f"Error when executing {binary}: {e}")
        os.chdir(owd)
        return None

    os.chdir(owd)

    return output


def generate_binaries():
    for output_name, flags in tqdm(GENERATION_FLAGS):
        print(f"Generating {output_name} with flags {flags}")

        exec_in_context(GENERATION_SOURCE_DIR, "make", ["clean"])
        exec_in_context(GENERATION_SOURCE_DIR, "./configure", flags)
        exec_in_context(GENERATION_SOURCE_DIR, "make", ["-j4"])
        exec_in_context(
            GENERATION_SOURCE_DIR,
            "cp",
            ["tcc", f"../{GENERATION_TARGET_DIR}/{output_name}"],
        )


def run_hyperfine():
    for name, _ in GENERATION_FLAGS:
        exec_in_context(
            ".",
            "hyperfine",
            [
                "--export-json",
                f"{REPORT_DIR}/{name}.json",
                "-w",
                "10",
                "-r",
                "200",
                f"{GENERATION_TARGET_DIR}/{name} -I{INCLUDE_PATH} -c {TEST_C_FILE}",
            ],
        )


def parse_reports_output_txt():
    """Parses the output of the hyperfine reports and prints the name
    of the file, the mean time, standard deviation"""

    for name, _ in GENERATION_FLAGS:
        with open(f"{REPORT_DIR}/{name}.json", "r") as f:
            ob = json.load(f)

            print(
                f"{name},{ob['results'][0]['mean'] * 1000:0.2f},{ob['results'][0]['stddev'] * 1000:0.2f}"
            )


def run_massif():
    for name, _ in GENERATION_FLAGS:
        exec_in_context(
            ".",
            "valgrind",
            [
                "--tool=massif",
                "--stacks=yes",
                "--pages-as-heap=yes",
                f"--massif-out-file=./{REPORT_DIR}/{name}.massif.out",
                f"{GENERATION_TARGET_DIR}/{name}",
                f"-I{INCLUDE_PATH}",
                "-c",
                f"{TEST_C_FILE}",
            ],
        )


def run_time():
    for name, _ in GENERATION_FLAGS:
        if "asan" in name:
            continue

        classic = exec_in_context(
            ".",
            "/usr/bin/time",
            [
                "-f",
                "%M",
                f"{GENERATION_TARGET_DIR}/{name}",
                f"-I{INCLUDE_PATH}",
                "-c",
                f"{TEST_C_FILE}",
            ],
            stderr=subprocess.STDOUT,
        ).split("\n")[-2]

        memcheck = exec_in_context(
            ".",
            "/usr/bin/time",
            [
                "-f",
                "%M",
                "valgrind",
                "--tool=memcheck",
                f"{GENERATION_TARGET_DIR}/{name}",
                f"-I{INCLUDE_PATH}",
                "-c",
                f"{TEST_C_FILE}",
            ],
            stderr=subprocess.STDOUT,
        ).split("\n")[-2]

        classic_mb = int(classic) / 1024.0
        memcheck_mb = int(memcheck) / 1024.0

        print(f"{name},{classic_mb},{memcheck_mb}")


def run_time_no_instrumentation():
    for name, _ in GENERATION_FLAGS:
        classic = exec_in_context(
            ".",
            "/usr/bin/time",
            [
                "-f",
                "%M",
                f"{GENERATION_TARGET_DIR}/{name}",
                f"-I{INCLUDE_PATH}",
                "-c",
                f"{TEST_C_FILE}",
            ],
            stderr=subprocess.STDOUT,
        ).split("\n")[-2]

        classic_mb = int(classic) / 1024.0

        print(f"{name},{classic_mb}")


def main():
    print(f"{len(GENERATION_FLAGS)} configurations available!")

    if len(sys.argv) == 1 or sys.argv[1] == "gen":
        generate_binaries()

    if len(sys.argv) == 1 or sys.argv[1] == "hyper":
        run_hyperfine()

    if len(sys.argv) == 1 or sys.argv[1] == "out":
        parse_reports_output_txt()

    if len(sys.argv) == 1 or sys.argv[1] == "massif":
        run_massif()

    if len(sys.argv) == 1 or sys.argv[1] == "time":
        run_time()

    if len(sys.argv) == 1 or sys.argv[1] == "time_no_instr":
        run_time_no_instrumentation()


if __name__ == "__main__":
    main()
