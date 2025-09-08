# nmap service 

#!/usr/bin/env python3
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Any, Dict
import subprocess, os, time, xml.etree.ElementTree as ET, ipaddress
from datetime import datetime

app = FastAPI(title="NmapScanService", version="2.2")

# ----- REQUEST MODEL -----
class ScanRequest(BaseModel):
    target: str = Field(..., description="IPv4/IPv6 IP address")
    full: Optional[bool] = Field(False, description="Run aggressive scan if true")
    ports: Optional[str] = Field("1-1024", description="Port range, default 1-1024")
    confirm: bool = Field(False, description="Must be true to authorize scan")

# ----- helpers -----
def get_nmap_path() -> str:
    # Linux path cho Docker
    nmap_path = "/usr/bin/nmap"
    if not os.path.isfile(nmap_path):
        raise HTTPException(status_code=500, detail=f"Nmap not found at {nmap_path}")
    return nmap_path


def build_cmd(nmap_bin: str, req: ScanRequest) -> list:
    args = [nmap_bin, "-oX", "-"]

    if req.full:
        # Quét toàn diện: top 1000 ports + service detect + OS detect
        args += ["-sS", "-A", "-T4", "-Pn", "--top-ports", "1000", "--reason"]
    else:
        args += ["-sS", "-sV", "-sC", "-Pn", "-T4", "--reason", "-p", req.ports]

    # 👇 BẮT BUỘC thêm target ở cuối
    args.append(req.target)
    return args

def run_nmap(cmd: list, timeout: int = 600):
    started = time.time()
    proc = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=timeout
    )
    elapsed = time.time() - started
    return proc.returncode, proc.stdout, proc.stderr, elapsed

def parse_xml(xml_string: str) -> Dict[str, Any]:
    root = ET.fromstring(xml_string)
    result = {"hosts": []}
    for host in root.findall("host"):
        h = {"addresses": [], "hostnames": [], "status": {}, "ports": [], "os": {"matches": []}, "scripts": []}
        st = host.find("status")
        if st is not None:
            h["status"] = st.attrib
        for addr in host.findall("address"):
            h["addresses"].append(addr.attrib)
        hn = host.find("hostnames")
        if hn is not None:
            for name in hn.findall("hostname"):
                h["hostnames"].append(name.attrib)
        ports = host.find("ports")
        if ports is not None:
            for p in ports.findall("port"):
                portinfo = p.attrib.copy()
                state = p.find("state")
                svc = p.find("service")
                if state is not None:
                    portinfo["state"] = state.attrib
                if svc is not None:
                    portinfo["service"] = svc.attrib
                scripts = []
                for scr in p.findall("script"):
                    s = scr.attrib.copy()
                    if scr.text:
                        s["output"] = scr.text.strip()
                    scripts.append(s)
                if scripts:
                    portinfo["scripts"] = scripts
                h["ports"].append(portinfo)
        os_tag = host.find("os")
        if os_tag is not None:
            matches = [m.attrib for m in os_tag.findall("osmatch")]
            h["os"]["matches"] = matches
        result["hosts"].append(h)
    return result

# ----- ENDPOINTS -----
@app.post("/nmap")
def scan(req: ScanRequest):
    if not req.confirm:
        raise HTTPException(status_code=400, detail="You must set confirm=true to authorize scan.")

    try:
        ipaddress.ip_address(req.target)
    except Exception:
        raise HTTPException(status_code=400, detail="Target must be a valid IP address.")

    nmap_bin = get_nmap_path()
    cmd = build_cmd(nmap_bin, req)
    started = datetime.utcnow().isoformat() + "Z"

    try:
        rc, out, err, elapsed = run_nmap(cmd)
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Scan timed out")

    if not out or not out.strip().startswith("<?xml"):
        raise HTTPException(status_code=500, detail=f"Nmap failed: {err[:500]}")

    parsed = parse_xml(out)

    return {
        "target": req.target,
        "nmap_command": " ".join(cmd),
        "return_code": rc,
        "stderr": err,
        "started_at": started,
        "elapsed_seconds": elapsed,
        "report": parsed
    }

@app.get("/health")
def health():
    try:
        nmap_bin = get_nmap_path()
        return {"status": "ok", "nmap_path": nmap_bin}
    except Exception as e:
        return {"status": "error", "detail": str(e)}
