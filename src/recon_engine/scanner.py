import shutil
import subprocess
from pathlib import Path
from typing import Any


def run_nmap(target: str, out_dir: Path, logger) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)

    xml_path = out_dir / "nmap.xml"
    txt_path = out_dir / "nmap.txt"
    run_log_path = out_dir / "nmap_run.log"

    if not shutil.which("nmap"):
        message = "nmap binary not found. Install nmap on Kali and ensure it is on PATH."
        run_log_path.write_text(message + "\n", encoding="utf-8")
        logger.error(message)
        return {
            "target": target,
            "xml_path": str(xml_path),
            "txt_path": str(txt_path),
            "run_log_path": str(run_log_path),
            "returncode": 127,
            "error": message,
        }

    cmd = [
        "nmap",
        "-sS",
        "-sV",
        "-O",
        "-oX",
        str(xml_path),
        "-oN",
        str(txt_path),
        target,
    ]

    logger.info("Running nmap scan: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    run_log_path.write_text((result.stdout or "") + "\n" + (result.stderr or ""), encoding="utf-8")

    scan_result: dict[str, Any] = {
        "target": target,
        "xml_path": str(xml_path),
        "txt_path": str(txt_path),
        "run_log_path": str(run_log_path),
        "returncode": result.returncode,
    }
    if result.returncode != 0:
        err = f"nmap exited with non-zero status {result.returncode}. See {run_log_path}"
        logger.error(err)
        scan_result["error"] = err
    else:
        logger.info("nmap scan completed successfully")

    return scan_result
