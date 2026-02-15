import json
import shutil
import subprocess


def _run_tool(cmd, output_path):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        output_path.write_text(result.stdout + "\n" + result.stderr)
        return {"cmd": " ".join(cmd), "returncode": result.returncode, "output": str(output_path)}
    except Exception as exc:
        output_path.write_text(f"tool failure: {exc}\n")
        return {"cmd": " ".join(cmd), "returncode": -1, "error": str(exc), "output": str(output_path)}


def run_recon(target, run_ctx):
    run_ctx.raw_dir.mkdir(parents=True, exist_ok=True)
    findings = {"target": target, "tools": []}
    nmap_xml = run_ctx.raw_dir / "nmap.xml"

    if shutil.which("nmap"):
        cmd = ["nmap", "-sV", "-O", "--top-ports", "200", "-T3", "-oX", str(nmap_xml), "-oN", str(run_ctx.raw_dir / "nmap.txt"), target]
        findings["tools"].append(_run_tool(cmd, run_ctx.raw_dir / "nmap_exec.log"))
    else:
        (run_ctx.raw_dir / "nmap_exec.log").write_text("nmap missing\n")
        findings["tools"].append({"cmd": "nmap", "returncode": -1, "error": "nmap missing"})

    optional = {
        "whatweb": ["whatweb", f"http://{target}"],
        "naabu": ["naabu", "-host", target],
        "amass": ["amass", "intel", "-active", "-addr", target],
        "httprobe": ["httprobe"],
    }
    for tool, cmd in optional.items():
        if shutil.which(tool):
            findings["tools"].append(_run_tool(cmd, run_ctx.raw_dir / f"{tool}.log"))
        else:
            (run_ctx.raw_dir / f"{tool}.log").write_text(f"{tool} missing (optional)\n")
            findings["tools"].append({"cmd": tool, "returncode": -1, "error": "optional tool missing"})

    (run_ctx.raw_dir / "recon_summary.json").write_text(json.dumps(findings, indent=2))
    return {"nmap_xml": str(nmap_xml), "summary": findings}
