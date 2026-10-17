"""Shaher laptop worker v1 (adds ONE fixed ffmpeg_test job; everything else still refused).
Outbound HTTPS only. Whitelisted job types. Signed jobs only. No shell, no arbitrary code from the bot.
Usage: worker.py --enroll CODE --bot URL --root DIR   (one time)
       worker.py --run --bot URL --root DIR            (loop)"""
import argparse, base64, hashlib, hmac, json, os, subprocess, sys, time, urllib.request, urllib.error, shutil, pathlib

ALLOWED = {"render", "browser_task", "wan_generate", "blender", "ping", "ffmpeg_test"}
VERSION = 1
POLL_SECS = 20

def http(bot, path, token=None, body=None, timeout=40):
    req = urllib.request.Request(bot + path, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"content-type": "application/json", **({"authorization": "Bearer " + token} if token else {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode() or "{}")

def log(root, msg):
    p = pathlib.Path(root) / "worker.log"
    if p.exists() and p.stat().st_size > 2_000_000: p.rename(p.with_suffix(".log.old"))
    with open(p, "a", encoding="utf-8") as f: f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + msg + "\n")

def enroll(a):
    r = http(a.bot, "/worker/enroll", body={"code": a.enroll.strip(), "host": os.environ.get("COMPUTERNAME", "pc")})
    pathlib.Path(a.root, "token").write_text(r["token"]); pathlib.Path(a.root, "signkey").write_text(r["signkey"])
    log(a.root, "enrolled")

def verify(job, key):
    """Bot signs {id,type,payload,exp} with HMAC-SHA256 using a per-worker key issued at enrollment (v0). Ed25519 manifest signing for code updates comes later."""
    msg = json.dumps({k: job[k] for k in ("id", "type", "payload", "exp")}, sort_keys=True, separators=(",", ":")).encode()
    good = hmac.new(key.encode(), msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(good, job.get("sig", "")) and job["exp"] > time.time()

def run_job(a, job):
    t = job["type"]; jd = pathlib.Path(a.root, "jobs", job["id"]); jd.mkdir(parents=True, exist_ok=True)
    try:
        if t == "ping": return {"ok": True, "pong": time.time()}
        if t == "ffmpeg_test": return ffmpeg_test(a.root, jd)
        if t == "render": return {"ok": False, "error": "render handler not implemented yet"}
        if t == "browser_task": return {"ok": False, "error": "browser_task handler not implemented yet"}
        if t == "wan_generate": return {"ok": False, "error": "WanGP not installed (needs Shaher's approval)"}
        if t == "blender": return {"ok": False, "error": "blender sandbox not available; refusing to run unsandboxed"}
        return {"ok": False, "error": "unknown type"}
    finally:
        shutil.rmtree(jd, ignore_errors=True)

def loop(a):
    tok = pathlib.Path(a.root, "token").read_text().strip(); key = pathlib.Path(a.root, "signkey").read_text().strip()
    stop = pathlib.Path(a.root, "STOP")
    while not stop.exists():
        try:
            r = http(a.bot, "/worker/poll", token=tok, body={"gpu": gpu_info(), "v": VERSION, "ffmpeg": bool(find_ffmpeg(a.root))})
            job = r.get("job")
            if job:
                if job.get("type") not in ALLOWED or not verify(job, key):
                    log(a.root, "REJECTED job %s type=%s" % (job.get("id"), job.get("type")))
                    http(a.bot, "/worker/result", token=tok, body={"id": job.get("id"), "ok": False, "error": "rejected"}); continue
                log(a.root, "job %s %s start; payload=%s" % (job["id"], job["type"], json.dumps(job["payload"], ensure_ascii=False)[:2000]))
                res = run_job(a, job)
                http(a.bot, "/worker/result", token=tok, body={"id": job["id"], **res}); log(a.root, "job %s done ok=%s" % (job["id"], res.get("ok")))
                continue
        except Exception as e:
            log(a.root, "poll error: " + str(e)[:200])
        time.sleep(POLL_SECS)
    log(a.root, "STOP file found, exiting")

def find_ffmpeg(root):
    p = pathlib.Path(root, "ffmpeg", "bin", "ffmpeg.exe")
    if p.exists(): return str(p)
    return shutil.which("ffmpeg")

def ffmpeg_test(root, jd):
    """ONE fixed command, no payload is used. Input is a synthetic test pattern, output goes only inside the job work folder, file protocol only (no network)."""
    ff = find_ffmpeg(root)
    if not ff: return {"ok": False, "error": "ffmpeg not found (run Update.bat)"}
    out = pathlib.Path(jd, "test.mp4"); res = {"ffmpeg": ff}
    v = subprocess.run([ff, "-hide_banner", "-version"], capture_output=True, text=True, timeout=20, cwd=str(jd))
    res["version"] = (v.stdout.splitlines() or ["?"])[0][:120]
    cmd = [ff, "-hide_banner", "-loglevel", "error", "-y", "-protocol_whitelist", "file", "-f", "lavfi", "-i", "testsrc=duration=2:size=320x180:rate=15",
           "-f", "lavfi", "-i", "sine=frequency=440:duration=2", "-c:v", "libx264", "-pix_fmt", "yuv420p", "-c:a", "aac", "-shortest", str(out)]
    t0 = time.time(); r = subprocess.run(cmd, capture_output=True, text=True, timeout=90, cwd=str(jd)); res["encode_sec"] = round(time.time() - t0, 2)
    if r.returncode != 0 or not out.exists(): return {"ok": False, "error": "ffmpeg failed: " + (r.stderr or "")[:300], **res}
    data = out.read_bytes(); res["bytes"] = len(data); res["sha256"] = hashlib.sha256(data).hexdigest()
    e = subprocess.run([ff, "-hide_banner", "-encoders"], capture_output=True, text=True, timeout=20, cwd=str(jd))
    res["nvenc"] = "h264_nvenc" in e.stdout
    return {"ok": True, **res}

def gpu_info():
    try:
        return subprocess.run(["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"], capture_output=True, text=True, timeout=8).stdout.strip() or "none"
    except Exception: return "none"

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--enroll"); ap.add_argument("--run", action="store_true"); ap.add_argument("--bot", required=True); ap.add_argument("--root", required=True)
    a = ap.parse_args(); os.makedirs(a.root, exist_ok=True)
    if a.enroll: enroll(a)
    elif a.run: loop(a)
