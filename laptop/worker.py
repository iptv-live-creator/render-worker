"""Shaher laptop worker v2 (fixed jobs: ping, ffmpeg_test, nvenc_test; signed self-update; everything else refused).
Outbound HTTPS only. Whitelisted job types. Signed jobs only. No shell, no arbitrary code from the bot.
Usage: worker.py --enroll CODE --bot URL --root DIR   (one time)
       worker.py --run --bot URL --root DIR            (loop)"""
import argparse, base64, re, hashlib, hmac, json, os, subprocess, sys, time, urllib.request, urllib.error, shutil, pathlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
ALLOWED = {"render", "browser_task", "wan_generate", "blender", "ping", "ffmpeg_test", "nvenc_test", "blender_test"}
VERSION = 3
POLL_SECS = 20
RESTART_CODE = 75
# Release signing PUBLIC key (Ed25519). The private key is not on the bot server and not on this PC.
PUBKEY = "9a80035809bf885c881a6df305918f2ed48e0c5b80598f46b202f8912b8144f1"
UPDATE_EVERY = 900          # seconds between update checks
UPDATABLE = {"worker.py", "ed25519_verify.py"}   # exact allow-list of files a signed manifest may replace
MAX_FILE = 1_000_000

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
        if t == "nvenc_test": return nvenc_test(a.root, jd)
        if t == "blender_test": return blender_test(a.root, jd)
        if t == "render": return {"ok": False, "error": "render handler not implemented yet"}
        if t == "browser_task": return {"ok": False, "error": "browser_task handler not implemented yet"}
        if t == "wan_generate": return {"ok": False, "error": "WanGP not installed (needs Shaher's approval)"}
        if t == "blender": return {"ok": False, "error": "blender sandbox not available; refusing to run unsandboxed"}
        return {"ok": False, "error": "unknown type"}
    finally:
        shutil.rmtree(jd, ignore_errors=True)


# ---------------- signed self-update ----------------
def _rj(path, default):
    try: return json.loads(pathlib.Path(path).read_text())
    except Exception: return default

def current_seq(root): return int(_rj(pathlib.Path(root, "update_seq"), 0) or 0)

def check_update(root, bot, pub_hex=PUBKEY, now=None, fetch=None):
    """Returns (status, detail). Applies a new release ONLY if: signature valid for the pinned key, not expired, sequence strictly newer
    than the installed one and not previously rolled back, every file name is in UPDATABLE, size and sha256 match. Never runs downloaded code here."""
    from ed25519_verify import verify
    now = now or time.time()
    fetch = fetch or (lambda path: _http_bytes(bot + path))
    try:
        mb = fetch("/worker/release/manifest.json"); sig = bytes.fromhex(fetch("/worker/release/manifest.sig").decode().strip())
    except Exception as e: return ("no-manifest", str(e)[:120])
    if not verify(bytes.fromhex(pub_hex), mb, sig): return ("refused", "bad signature")
    try: m = json.loads(mb.decode())
    except Exception: return ("refused", "manifest not json")
    seq = m.get("sequence"); exp = m.get("expires"); files = m.get("files")
    if not isinstance(seq, int) or not isinstance(exp, (int, float)) or not isinstance(files, list) or not files: return ("refused", "bad manifest shape")
    if exp < now: return ("refused", "manifest expired")
    if seq <= current_seq(root): return ("current", "seq %d" % seq)
    if seq in _rj(pathlib.Path(root, "bad_seqs.json"), []): return ("refused", "seq %d was rolled back before" % seq)
    staged = {}
    for f in files:
        name, sha, size = f.get("name"), f.get("sha256"), f.get("size")
        if name not in UPDATABLE or not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha) or not isinstance(size, int) or size <= 0 or size > MAX_FILE:
            return ("refused", "file not allowed: %s" % str(name)[:40])
        try: data = fetch("/worker/release/files/" + name)
        except Exception as e: return ("refused", "download failed: " + str(e)[:80])
        if len(data) != size or hashlib.sha256(data).hexdigest() != sha: return ("refused", "hash/size mismatch for %s" % name)
        if name.endswith(".py"):
            try: compile(data, name, "exec")
            except Exception: return ("refused", "does not compile: %s" % name)
        staged[name] = data
    r = pathlib.Path(root); bk = r / "backup"; shutil.rmtree(bk, ignore_errors=True); bk.mkdir()
    for name in staged:
        if (r / name).exists(): shutil.copy2(r / name, bk / name)
    (r / "pending.json").write_text(json.dumps({"seq": seq, "prev_seq": current_seq(root), "files": sorted(staged)}))
    for name, data in staged.items():
        tmp = r / (name + ".new"); tmp.write_bytes(data); os.replace(tmp, r / name)
    (r / "update_seq").write_text(str(seq))
    return ("applied", "seq %d files %s" % (seq, ",".join(sorted(staged))))

def _http_bytes(url, timeout=40):
    with urllib.request.urlopen(urllib.request.Request(url), timeout=timeout) as r: return r.read(MAX_FILE + 1)

def mark_healthy(root):
    p = pathlib.Path(root, "healthy.json"); seq = current_seq(root)
    if _rj(p, {}).get("seq") != seq: p.write_text(json.dumps({"seq": seq, "t": time.time()}))

def loop(a):
    tok = pathlib.Path(a.root, "token").read_text().strip(); key = pathlib.Path(a.root, "signkey").read_text().strip()
    stop = pathlib.Path(a.root, "STOP"); last_upd = 0
    while not stop.exists():
        try:
            if a.supervised and time.time() - last_upd > UPDATE_EVERY:
                last_upd = time.time(); st, det = check_update(a.root, a.bot); log(a.root, "update check: %s %s" % (st, det))
                if st == "applied": log(a.root, "restarting into new release"); sys.exit(RESTART_CODE)
            r = http(a.bot, "/worker/poll", token=tok, body={"gpu": gpu_info(), "v": VERSION, "seq": current_seq(a.root), "supervised": bool(a.supervised), "ffmpeg": bool(find_ffmpeg(a.root)), "blender": blender_version(a.root)})
            if a.supervised: mark_healthy(a.root)
            job = r.get("job")
            if job:
                if job.get("type") not in ALLOWED or not verify(job, key):
                    log(a.root, "REJECTED job %s type=%s" % (job.get("id"), job.get("type")))
                    http(a.bot, "/worker/result", token=tok, body={"id": job.get("id"), "ok": False, "error": "rejected"}); continue
                log(a.root, "job %s %s start; payload=%s" % (job["id"], job["type"], json.dumps(job["payload"], ensure_ascii=False)[:2000]))
                res = run_job(a, job)
                http(a.bot, "/worker/result", token=tok, body={"id": job["id"], **res}); log(a.root, "job %s done ok=%s" % (job["id"], res.get("ok")))
                continue
        except SystemExit: raise
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

def nvenc_test(root, jd):
    """ONE fixed command, no payload is used. Tries h264_nvenc on a synthetic input; output only inside the job work folder."""
    ff = find_ffmpeg(root)
    if not ff: return {"ok": False, "error": "ffmpeg not found"}
    out = pathlib.Path(jd, "nv.mp4")
    cmd = [ff, "-hide_banner", "-loglevel", "error", "-y", "-protocol_whitelist", "file", "-f", "lavfi", "-i", "testsrc=duration=2:size=640x360:rate=30",
           "-c:v", "h264_nvenc", "-pix_fmt", "yuv420p", str(out)]
    t0 = time.time(); r = subprocess.run(cmd, capture_output=True, text=True, timeout=90, cwd=str(jd)); sec = round(time.time() - t0, 2)
    if r.returncode != 0 or not out.exists(): return {"ok": False, "encode_sec": sec, "error": "nvenc failed: " + (r.stderr or "")[:400]}
    data = out.read_bytes()
    return {"ok": True, "encode_sec": sec, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "gpu": gpu_info()}

# ---------------- Blender (fixed script, shipped inside signed code; the bot can never send script text) ----------------
BLENDER_SCRIPT = """import bpy, os, json
bpy.ops.wm.read_factory_settings(use_empty=True)
sc = bpy.context.scene
sc.render.engine = 'CYCLES'
sc.cycles.device = 'CPU'; sc.cycles.samples = 4; sc.cycles.use_denoising = False
sc.render.resolution_x = 320; sc.render.resolution_y = 180; sc.render.resolution_percentage = 100
sc.render.image_settings.file_format = 'PNG'
sc.render.filepath = os.path.join(os.getcwd(), 'render.png')
bpy.ops.mesh.primitive_cube_add(size=2)
sun = bpy.data.objects.new('sun', bpy.data.lights.new('sun', 'SUN')); sc.collection.objects.link(sun); sun.rotation_euler = (0.8, 0.2, 0.6)
cam = bpy.data.objects.new('cam', bpy.data.cameras.new('cam')); sc.collection.objects.link(cam)
cam.location = (4.0, -4.0, 3.0); cam.rotation_euler = (1.1, 0.0, 0.8); sc.camera = cam
bpy.ops.render.render(write_still=True)
print('SW_RESULT ' + json.dumps({'blender': bpy.app.version_string}))
"""
_bl_cache = {"t": 0, "v": False, "exe": None}

def find_blender(root):
    c = [pathlib.Path(root, "blender", "blender.exe")]
    bases = []
    if os.environ.get("ProgramFiles"): bases.append(pathlib.Path(os.environ["ProgramFiles"], "Blender Foundation"))
    if os.environ.get("LOCALAPPDATA"): bases.append(pathlib.Path(os.environ["LOCALAPPDATA"], "Programs", "Blender Foundation"))
    for p in bases:
        if p.exists(): c += [d / "blender.exe" for d in sorted(p.glob("Blender *"), reverse=True)]
    for x in c:
        if x.exists(): return str(x)
    return None

def blender_version(root):
    """Cached (10 min). Returns the version line or False when Blender is not found."""
    if time.time() - _bl_cache["t"] < 600: return _bl_cache["v"]
    _bl_cache["t"] = time.time(); exe = find_blender(root); _bl_cache["exe"] = exe; _bl_cache["v"] = False
    if exe:
        try: _bl_cache["v"] = (subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=30).stdout.splitlines() or ["?"])[0][:60]
        except Exception: _bl_cache["v"] = False
    return _bl_cache["v"]

def blender_test(root, jd):
    """ONE fixed job, no payload is used. Runs Blender in background mode with factory settings, offline flag, cwd = job folder, hard timeout; renders one 320x180 Cycles CPU frame (no GPU/OpenGL needed)."""
    exe = find_blender(root)
    if not exe: return {"ok": False, "error": "Blender not found on this PC"}
    sp = pathlib.Path(jd, "scene.py"); sp.write_text(BLENDER_SCRIPT)
    cmd = [exe, "-b", "--factory-startup", "--offline-mode", "-noaudio", "--python", str(sp)]
    t0 = time.time()
    try: r = subprocess.run(cmd, capture_output=True, text=True, timeout=150, cwd=str(jd))
    except subprocess.TimeoutExpired: return {"ok": False, "error": "blender timed out (150 s), killed"}
    sec = round(time.time() - t0, 2); out = pathlib.Path(jd, "render.png")
    if r.returncode != 0 or not out.exists(): return {"ok": False, "render_sec": sec, "error": "blender failed rc=%s: %s" % (r.returncode, ((r.stderr or "") + (r.stdout or ""))[-400:])}
    data = out.read_bytes(); ver = ""
    for line in r.stdout.splitlines():
        if line.startswith("SW_RESULT "): ver = line[10:][:80]
    return {"ok": True, "render_sec": sec, "bytes": len(data), "png": data[:8] == b"\x89PNG\r\n\x1a\n", "sha256": hashlib.sha256(data).hexdigest(), "info": ver}

def gpu_info():
    try:
        return subprocess.run(["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"], capture_output=True, text=True, timeout=8).stdout.strip() or "none"
    except Exception: return "none"

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--enroll"); ap.add_argument("--run", action="store_true"); ap.add_argument("--bot", required=True); ap.add_argument("--root", required=True); ap.add_argument("--supervised", action="store_true")
    a = ap.parse_args(); os.makedirs(a.root, exist_ok=True)
    if a.enroll: enroll(a)
    elif a.run: loop(a)
