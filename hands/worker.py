"""Atlas Hands worker. Outbound HTTPS polling only. Runs ONLY the allowlisted tools below, built from validated args (never a shell string),
only for jobs signed by the server with this worker's key, unexpired and not seen before. Work happens inside WORKDIR only."""
import os, sys, json, time, hmac, hashlib, base64, re, subprocess, shutil, urllib.request, urllib.error, pathlib, platform

BASE = os.environ["HANDS_URL"].rstrip("/"); NAME = os.environ["HANDS_NAME"]; KEY = os.environ["HANDS_KEY"]
WORKDIR = pathlib.Path(os.environ.get("HANDS_DIR", "./jobs")).resolve(); WORKDIR.mkdir(parents=True, exist_ok=True)
SEEN = WORKDIR / "seen_nonces.txt"; STOP = WORKDIR / "STOP"
HERE = pathlib.Path(__file__).resolve().parent
TOKEN = hmac.new(KEY.encode(), ("auth|" + NAME).encode(), hashlib.sha256).hexdigest()
CHUNK = 450000
SAFE = re.compile(r"^[A-Za-z0-9_.-]{1,60}$")

def api(path, body=None, timeout=40):
    req = urllib.request.Request(BASE + path, data=None if body is None else json.dumps(body).encode(), method="GET" if body is None else "POST",
                                 headers={"x-worker": NAME, "x-token": TOKEN, "content-type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=timeout))

def verify(j):
    for f in ("id", "tool", "args", "exp", "nonce", "approved", "sig"):
        if f not in j: return "missing field " + f
    body = json.dumps({x: j[x] for x in ("id", "tool", "args", "exp", "nonce", "approved")}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if not j["sig"] or not hmac.compare_digest(hmac.new(KEY.encode(), body.encode(), hashlib.sha256).hexdigest(), j["sig"]): return "bad signature"
    if time.time() > j["exp"]: return "expired"
    seen = SEEN.read_text().split() if SEEN.exists() else []
    if j["nonce"] in seen: return "replayed"
    return ""

def mark_seen(n):
    with open(SEEN, "a") as f: f.write(n + "\n")

def inside(base, name):
    if not SAFE.match(str(name)) or name in (".", ".."): raise ValueError("unsafe file name")
    p = (base / name).resolve()
    if base.resolve() not in p.parents: raise ValueError("path outside job folder")
    return p

def run(cmd, cwd, timeout, jid):
    p = subprocess.Popen(cmd, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, shell=False)
    t0 = time.time(); out = []; last = 0
    try:
        while p.poll() is None:
            if time.time() - t0 > timeout: p.kill(); return -9, "timeout", "".join(out)[-1500:]
            if STOP.exists(): p.kill(); return -8, "stopped", "".join(out)[-1500:]
            time.sleep(0.5)
            if time.time() - last > 60: last = time.time(); api("/worker/hands/log", {"id": jid, "line": "running %ds" % (time.time() - t0)})
    finally:
        try: out.append(p.stdout.read() or "")
        except Exception: pass
    return p.returncode, "", "".join(out)[-1500:]

def num(a, k, lo, hi, d):
    v = a.get(k, d)
    if not isinstance(v, (int, float)) or isinstance(v, bool) or not lo <= v <= hi: raise ValueError("bad %s" % k)
    return v

def t_probe(a, d, jid):
    info = {"os": platform.platform(), "python": sys.version.split()[0]}
    for n, c in (("ffmpeg", ["ffmpeg", "-version"]), ("blender", ["blender", "--version"]), ("nvidia", ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"])):
        try: info[n] = subprocess.run(c, capture_output=True, text=True, timeout=20).stdout.strip().splitlines()[0][:120]
        except Exception: info[n] = None
    return {"info": info}, None

def t_ffmpeg_testsrc(a, d, jid):
    sec = num(a, "seconds", 1, 120, 3); w = int(num(a, "width", 160, 1920, 640)); h = int(num(a, "height", 90, 1080, 360))
    out = inside(d, "out.mp4")
    code, why, tail = run(["ffmpeg", "-y", "-f", "lavfi", "-i", "testsrc2=size=%dx%d:rate=24" % (w, h), "-t", str(sec), "-pix_fmt", "yuv420p", str(out)], d, 600, jid)
    return {"exit": code, "tail": tail, "reason": why}, (out if code == 0 else None)

def t_ffmpeg_convert(a, d, jid):
    src = inside(d, a.get("input", "in.mp4")); out = inside(d, "out.mp4")
    if not src.exists(): raise ValueError("input missing")
    code, why, tail = run(["ffmpeg", "-y", "-i", str(src), "-c:v", "libx264", "-crf", str(int(num(a, "crf", 18, 32, 23))), "-pix_fmt", "yuv420p", "-c:a", "aac", str(out)], d, 900, jid)
    return {"exit": code, "tail": tail, "reason": why}, (out if code == 0 else None)

def t_blender_render(a, d, jid):
    tpl = a.get("template", "title_card")
    if tpl not in ("title_card", "room_bedroom"): raise ValueError("unknown template")
    spec = {"text": str(a.get("text", ""))[:80], "frames": int(num(a, "frames", 1, 240, 1)), "res": [int(num(a, "width", 160, 1920, 640)), int(num(a, "height", 90, 1080, 360))],
            "samples": int(num(a, "samples", 1, 256, 24)), "gpu": bool(a.get("gpu")), "denoise": bool(a.get("denoise")), "palette": a.get("palette", "warm") if a.get("palette") in ("warm", "cool") else "warm"}
    for k in ("hdri", "floor_tex"):
        v = a.get(k)
        if v is not None:
            if not isinstance(v, str) or not re.match(r"^[a-z0-9_]{2,50}$", v): raise ValueError("bad " + k)
            spec[k] = v
    pr = a.get("props")
    if pr is not None:
        if not isinstance(pr, list) or len(pr) > 6: raise ValueError("bad props")
        spec["props"] = []
        for p in pr:
            if not isinstance(p, dict) or not isinstance(p.get("id"), str) or not re.match(r"^[a-z0-9_]{2,50}$", p["id"]): raise ValueError("bad prop id")
            spec["props"].append({"id": p["id"], "x": num(p, "x", -2.3, 2.3, 0), "y": num(p, "y", -2.3, 2.3, 0), "rz": num(p, "rz", -360, 360, 0)})
    (d / "spec.json").write_text(json.dumps(spec, ensure_ascii=False))
    exe = os.environ.get("BLENDER", "blender"); frames = d / "frames"
    code, why, tail = run([exe, "-b", "-noaudio", "-P", str(HERE / "blender" / (tpl + ".py")), "--", str(d / "spec.json"), str(frames if tpl == "room_bedroom" else d / "out.png")], d, 1500, jid)
    if code != 0 or why: return {"exit": code, "tail": tail, "reason": why}, None
    if tpl == "title_card": return {"exit": 0, "tail": tail}, (d / "out.png")
    ass = ""
    try: ass = (d / "assets.json").read_text()[:600]
    except Exception: pass
    if spec["frames"] == 1: return {"exit": 0, "tail": tail, "info": ass}, (frames / "f_0001.png")
    out = d / "out.mp4"
    code, why, t2 = run(["ffmpeg", "-y", "-framerate", "24", "-i", str(frames / "f_%04d.png"), "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "20", str(out)], d, 600, jid)
    return {"exit": code, "tail": t2, "reason": why, "info": ass}, (out if code == 0 else None)

TOOLS = {"probe": t_probe, "ffmpeg_testsrc": t_ffmpeg_testsrc, "ffmpeg_convert": t_ffmpeg_convert, "blender_render": t_blender_render}

def upload(jid, f):
    data = f.read_bytes(); b = base64.b64encode(data).decode(); n = 0
    for i in range(0, len(b), CHUNK * 4 // 3):
        for attempt in range(3):
            try:
                if api("/worker/hands/chunk", {"id": jid, "n": n, "data": b[i:i + CHUNK * 4 // 3]}).get("ok"): break
            except Exception: time.sleep(2)
        else: raise RuntimeError("chunk upload failed")
        n += 1
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "chunks": n}

def handle(j):
    jid = j.get("id", "?")
    bad = verify(j)
    if bad: api("/worker/hands/done", {"id": jid, "status": "refused", "reason": bad}); print("REFUSED", jid, bad); return
    mark_seen(j["nonce"])
    if j["tool"] not in TOOLS:
        api("/worker/hands/done", {"id": jid, "status": "needs_approval", "reason": "tool not in allowlist: " + str(j["tool"])[:40]}); print("NEEDS_APPROVAL", jid); return
    d = WORKDIR / jid; d.mkdir(exist_ok=True)
    try:
        res, f = TOOLS[j["tool"]](j["args"] if isinstance(j["args"], dict) else {}, d, jid)
        if f is not None and f.exists(): res.update(upload(jid, f))
        res["status"] = "done" if (res.get("exit", 0) == 0 and not res.get("reason")) else "failed"
        api("/worker/hands/done", dict(res, id=jid)); print("DONE", jid, res.get("status"))
    except ValueError as e: api("/worker/hands/done", {"id": jid, "status": "refused", "reason": "args: " + str(e)[:80]}); print("REFUSED args", jid, e)
    except Exception as e: api("/worker/hands/done", {"id": jid, "status": "failed", "reason": str(e)[:120]}); print("FAILED", jid, e)
    finally: shutil.rmtree(d, ignore_errors=True)

def main():
    until = time.time() + float(os.environ.get("HANDS_MAX_SECONDS", "0") or 0) if os.environ.get("HANDS_MAX_SECONDS") else None
    idle = 0
    while not STOP.exists():
        if until and time.time() > until: break
        try:
            j = api("/worker/hands/next").get("job")
            if j: idle = 0; handle(j); continue
        except Exception as e: print("poll error", str(e)[:80]); time.sleep(10)
        idle += 1; time.sleep(3 if idle < 40 else 30)
    print("worker stopped")

if __name__ == "__main__": main()
