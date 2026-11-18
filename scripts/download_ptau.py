#!/usr/bin/env python3
"""Resumable byte-range SRS transfer; the caller verifies the pinned full digest."""
import concurrent.futures
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

url, target = sys.argv[1], Path(sys.argv[2])
head = subprocess.run(["curl", "--noproxy", "*", "--fail", "--silent", "--show-error", "--head", "--location", "--retry", "3", "--max-time", "30", url], capture_output=True, text=True)
if head.returncode:
    print(head.stderr, file=sys.stderr, flush=True)
    head.check_returncode()
head = head.stdout
total = int(re.findall(r"content-length:\s*(\d+)", head, re.I)[-1])
manifest = Path(str(target)+".ranges.json")
if manifest.exists():
    state = json.loads(manifest.read_text())
    if state["url"] != url or state["total"] != total:
        raise RuntimeError("TRANSFER_MANIFEST_MISMATCH")
else:
    state = {"url": url, "total": total, "prefix": target.stat().st_size if target.exists() else 0, "completed": []}
    if state["prefix"] > total:
        raise RuntimeError("PARTIAL_FILE_TOO_LARGE")
def checkpoint():
    temp = Path(str(manifest)+".tmp")
    temp.write_text(json.dumps(state))
    os.replace(temp, manifest)
checkpoint()
chunk_size = state.get("chunk_size", 64*1024*1024 if state["completed"] else 16*1024*1024)
state["chunk_size"] = chunk_size
checkpoint()
ranges = [(a, min(a+chunk_size, total)-1) for a in range(state["prefix"], total, chunk_size) if a not in state["completed"]]
def download(interval):
    a,b = interval
    file, headers = Path(f"{target}.chunk-{a}"), Path(f"{target}.headers-{a}")
    for attempt in range(4):
        result = subprocess.run(["curl", "--noproxy", "*", "--fail", "--silent", "--show-error", "--location", "--connect-timeout", "20", "--max-time", "180", "--speed-time", "45", "--speed-limit", "1024", "--range", f"{a}-{b}", "--max-filesize", str(b-a+1), "--dump-header", str(headers), "-o", str(file), url+f"?rcpeh-range={a}-{b}"], capture_output=True, text=True)
        matches = re.findall(r"content-range:\s*bytes\s+(\d+)-(\d+)/(\d+)", headers.read_text() if headers.exists() else "", re.I)
        if result.returncode == 0 and matches and tuple(map(int,matches[-1])) == (a,b,total) and file.stat().st_size == b-a+1:
            headers.unlink(missing_ok=True)
            return a,b,file
        print(json.dumps({"range_start":a,"attempt":attempt,"exit_code":result.returncode,"error":result.stderr.strip()}),flush=True)
        time.sleep(min(2**attempt, 8))
    raise RuntimeError(f"RANGE_TRANSFER_FAILED_{a}")
def merge(out, a, b, file):
    with file.open("rb") as part:
        offset=a
        while data:=part.read(1024*1024):
            out.seek(offset);out.write(data);offset+=len(data)
    if offset != b + 1:
        raise RuntimeError(f"RANGE_SIZE_MISMATCH_{a}")
    out.flush();os.fsync(out.fileno())
    state["completed"].append(a);checkpoint()
    complete=state["prefix"]+sum(min(chunk_size,total-start) for start in state["completed"])
    print(json.dumps({"received_bytes":complete,"total_bytes":total,"digest_verification":"PENDING"}),flush=True)

with target.open("r+b" if target.exists() else "w+b") as out:
    out.truncate(total)
    # A prior invocation can be interrupted after a worker has validated a
    # range but before the main thread merges it. Adopt only exact-size cached
    # chunks; the final pinned BLAKE2b digest remains the integrity authority.
    completed=set(state["completed"])
    for a,b in ranges:
        file=Path(f"{target}.chunk-{a}")
        if file.exists() and file.stat().st_size == b-a+1:
            merge(out,a,b,file)
            completed.add(a)
    ranges=[(a,b) for a,b in ranges if a not in completed]
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        failures=[]
        futures=[pool.submit(download,r) for r in ranges]
        for future in concurrent.futures.as_completed(futures):
            try:
                a,b,file = future.result()
                merge(out,a,b,file)
            except Exception as e:
                failures.append(e)
        if failures:
            raise failures[0]
print(json.dumps({"transfer_complete":True,"bytes":total,"digest_verification":"PENDING"}),flush=True)
