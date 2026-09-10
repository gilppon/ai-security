import subprocess
import sys


def test_jailbreak_detector_imports_in_fresh_interpreter() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "from input_security.jailbreak.detector import JailbreakDetector; JailbreakDetector()",
        ],
        cwd=".",
        shell=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0, completed.stderr
