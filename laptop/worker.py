"""Shaher laptop worker v2 (fixed jobs: ping, ffmpeg_test, nvenc_test; signed self-update; everything else refused).
Outbound HTTPS only. Whitelisted job types. Signed jobs only. No shell, no arbitrary code from the bot.
Usage: worker.py --enroll CODE --bot URL --root DIR   (one time)
       worker.py --run --bot URL --root DIR            (loop)"""
import threading, argparse, base64, re, hashlib, hmac, json, os, subprocess, sys, time, urllib.request, urllib.error, shutil, pathlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
ALLOWED = {"render", "browser_task", "wan_generate", "blender", "ping", "ffmpeg_test", "nvenc_test", "blender_test", "blender_video"}
VERSION = 11
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
        if t == "blender_video": return blender_video(a.root, jd, job.get("payload") or {})
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

MAX_ART = 8_000_000
def upload_artifact(a, tok, jid, name, data):
    """Sends ONE result file (made by a fixed job, <= 8 MB) to the bot in chunks. Outbound only."""
    if len(data) > MAX_ART: raise ValueError("artifact too big")
    step = 250_000; chunks = [data[i:i + step] for i in range(0, len(data), step)] or [b""]
    for i, c in enumerate(chunks):
        http(a.bot, "/worker/artifact", token=tok, body={"id": jid, "idx": i, "total": len(chunks), "b64": base64.b64encode(c).decode()}, timeout=60)
    return {"name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "chunks": len(chunks)}

def loop(a):
    tok = pathlib.Path(a.root, "token").read_text().strip(); key = pathlib.Path(a.root, "signkey").read_text().strip()
    stop = pathlib.Path(a.root, "STOP"); last_upd = 0
    while not stop.exists():
        try:
            if a.supervised and time.time() - last_upd > UPDATE_EVERY:
                last_upd = time.time(); st, det = check_update(a.root, a.bot); log(a.root, "update check: %s %s" % (st, det))
                if st == "applied": log(a.root, "restarting into new release"); sys.exit(RESTART_CODE)
            r = http(a.bot, "/worker/poll", token=tok, body={"gpu": gpu_info(), "v": VERSION, "seq": current_seq(a.root), "supervised": bool(a.supervised), "ffmpeg": bool(find_ffmpeg(a.root)), "blender": blender_version(a.root), "resolve": resolve_info(), "power": power_state()})
            if a.supervised: mark_healthy(a.root)
            job = r.get("job")
            if job:
                if job.get("type") not in ALLOWED or not verify(job, key):
                    log(a.root, "REJECTED job %s type=%s" % (job.get("id"), job.get("type")))
                    http(a.bot, "/worker/result", token=tok, body={"id": job.get("id"), "ok": False, "error": "rejected"}); continue
                log(a.root, "job %s %s start; payload=%s" % (job["id"], job["type"], json.dumps(job["payload"], ensure_ascii=False)[:2000]))
                res = run_job(a, job)
                art = res.pop("_art", None)
                if art:
                    try: res["artifact"] = upload_artifact(a, tok, job["id"], art[0], art[1])
                    except Exception as e: res["artifact_error"] = str(e)[:150]
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
    if r.returncode != 0 or not out.exists(): return {"ok": False, "render_sec": sec, "device_line": devline, "power_start": pw0, "error": "blender failed rc=%s: %s" % (r.returncode, ((r.stderr or "") + (r.stdout or ""))[-400:])}
    data = out.read_bytes(); ver = ""
    for line in r.stdout.splitlines():
        if line.startswith("SW_RESULT "): ver = line[10:][:80]
    return {"ok": True, "render_sec": sec, "bytes": len(data), "png": data[:8] == b"\x89PNG\r\n\x1a\n", "sha256": hashlib.sha256(data).hexdigest(), "info": ver, "_art": ("render.png", data)}

# Fixed scene "orbit_rings". Script text lives here (signed code). The payload only picks validated numbers.
VIDEO_PRESETS = {"orbit_rings", "atlas_map", "baad_style"}
VIDEO_RES = {"360p": (640, 360), "540p": (960, 540), "720p": (1280, 720), "v540": (540, 960), "v720": (720, 1280)}
ATLAS_GEO_Z = "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"   # Natural Earth 110m country outlines (public domain), zlib+base64 JSON
ATLAS_SCRIPT = """import bpy, os, json, math
P = json.load(open(os.path.join(os.getcwd(), 'params.json')))
GEO = json.load(open(os.path.join(os.getcwd(), 'geo.json')))
FPS = 24; N = P['seconds'] * FPS
HL = set(P.get('countries') or ['EGY'])
bpy.ops.wm.read_factory_settings(use_empty=True)
sc = bpy.context.scene
sc.render.fps = FPS; sc.frame_start = 1; sc.frame_end = N
sc.render.resolution_x, sc.render.resolution_y = P['w'], P['h']; sc.render.resolution_percentage = 100
sc.render.engine = 'CYCLES'; sc.cycles.samples = P['samples']; sc.cycles.use_denoising = True
try: sc.cycles.denoiser = 'OPENIMAGEDENOISE'
except Exception: pass
sc.render.image_settings.file_format = 'PNG'
sc.render.filepath = os.path.join(os.getcwd(), 'frames', '')
dev = 'CPU'; dev_err = ''; dev_list = []
try:
    pr = bpy.context.preferences.addons['cycles'].preferences
    for t in ('OPTIX', 'CUDA'):
        pr.compute_device_type = t; pr.get_devices()
        g = [d for d in pr.devices if d.type == t]
        if g:
            for d in pr.devices: d.use = (d.type == t)
            sc.cycles.device = 'GPU'; dev = t; dev_list = [d.name for d in g]
            if t == 'OPTIX':
                try: sc.cycles.denoiser = 'OPTIX'
                except Exception: pass
            break
    if dev == 'CPU': dev_err = 'no gpu devices: ' + ','.join(d.type + ':' + d.name for d in pr.devices)[:150]
except Exception as e:
    dev = 'CPU'; dev_err = str(e)[:150]
print('SW_DEVICE ' + dev + ' ' + str(dev_list) + ' ' + dev_err, flush=True)
if dev == 'CPU' and not P.get('allow_cpu_dev'): raise SystemExit(3)
SX = 0.1
RR = 36.0 / (2 * math.pi)
def mx(lon): return lon * SX
def my(lat):
    lat = max(-84, min(84, lat)); return RR * math.log(math.tan(math.pi / 4 + math.radians(lat) / 2))
def solid(name, color, rough=0.55, emit=0.0):
    m = bpy.data.materials.new(name); m.use_nodes = True; nt = m.node_tree; nt.nodes.clear()
    o = nt.nodes.new('ShaderNodeOutputMaterial')
    if emit > 0:
        e = nt.nodes.new('ShaderNodeEmission'); e.inputs['Color'].default_value = color; e.inputs['Strength'].default_value = emit
        nt.links.new(e.outputs[0], o.inputs['Surface'])
    else:
        b = nt.nodes.new('ShaderNodeBsdfPrincipled'); b.inputs['Base Color'].default_value = color; b.inputs['Roughness'].default_value = rough
        nt.links.new(b.outputs[0], o.inputs['Surface'])
    return m
def curve_obj(name, rings, ext, mat):
    cu = bpy.data.curves.new(name, 'CURVE'); cu.dimensions = '2D'; cu.fill_mode = 'BOTH'; cu.extrude = ext
    for ring in rings:
        if len(ring) < 4: continue
        sp = cu.splines.new('POLY'); sp.points.add(len(ring) - 1)
        for i, (lon, lat) in enumerate(ring): sp.points[i].co = (mx(lon), my(lat), 0, 1)
        sp.use_cyclic_u = True
    ob = bpy.data.objects.new(name, cu); sc.collection.objects.link(ob); cu.materials.append(mat); return ob
land, hl = [], []
for iso, polys in GEO:
    if iso == 'ATA': continue
    (hl if iso in HL else land).append((iso, polys))
PAL = [(0.62, 0.38, 0.14, 1), (0.50, 0.30, 0.10, 1), (0.58, 0.46, 0.16, 1), (0.42, 0.34, 0.12, 1), (0.66, 0.32, 0.10, 1), (0.54, 0.40, 0.18, 1)]
PM = [solid('land%d' % i, c, 0.8) for i, c in enumerate(PAL)]
for iso, polys in land:
    curve_obj('c_' + iso, polys, 0.03, PM[sum(ord(ch) for ch in iso) % len(PM)])
hobs = []
tx = ty = 0.0; cnt = 0
for iso, polys in hl:
    ob = curve_obj('hl_' + iso, polys, 0.25, solid('hl', (1.0, 0.25, 0.03, 1), 0, 1.4)); hobs.append(ob)
    big = max(polys, key=lambda r: len(r)); cx = sum(p[0] for p in big) / len(big); cy = sum(p[1] for p in big) / len(big)
    tx += mx(cx); ty += my(cy); cnt += 1
if cnt: tx /= cnt; ty /= cnt
else: tx, ty = 0, 10
bpy.ops.mesh.primitive_plane_add(size=400, location=(0, 0, -0.3))
sea = bpy.context.active_object; sea.data.materials.append(solid('sea', (0.02, 0.07, 0.17, 1), 0.35))
bpy.context.preferences.edit.keyframe_new_interpolation_type = 'BEZIER'
for ob in hobs:
    ob.scale[2] = 0.05; ob.keyframe_insert('scale', frame=1)
    ob.scale[2] = 1.0; ob.keyframe_insert('scale', frame=int(N * 0.55))
    ob.scale[2] = 1.6; ob.keyframe_insert('scale', frame=N)
cd = bpy.data.cameras.new('cam'); cd.lens = 38
cam = bpy.data.objects.new('cam', cd); sc.collection.objects.link(cam); sc.camera = cam
tgt = bpy.data.objects.new('tgt', None); sc.collection.objects.link(tgt)
tc = cam.constraints.new('TRACK_TO'); tc.target = tgt; tc.track_axis = 'TRACK_NEGATIVE_Z'; tc.up_axis = 'UP_Y'
cam.location = (0, -18, 52); cam.keyframe_insert('location', frame=1)
tgt.location = (0, 6, 0); tgt.keyframe_insert('location', frame=1)
cam.location = (tx, ty - 7.5, 9.5); cam.keyframe_insert('location', frame=N)
tgt.location = (tx, ty, 0); tgt.keyframe_insert('location', frame=N)
sun = bpy.data.lights.new('sun', 'SUN'); sun.energy = 2.6; sun.angle = math.radians(4)
so = bpy.data.objects.new('sun', sun); sc.collection.objects.link(so); so.rotation_euler = (math.radians(50), 0, math.radians(-30))
w = bpy.data.worlds.new('w'); sc.world = w; w.use_nodes = True
w.node_tree.nodes['Background'].inputs['Color'].default_value = (0.02, 0.05, 0.12, 1); w.node_tree.nodes['Background'].inputs['Strength'].default_value = 0.35
try: sc.view_settings.view_transform = 'Standard'
except Exception: pass
if P.get('still'):
    sc.frame_set(P['still']); sc.render.filepath = os.path.join(os.getcwd(), 'still.png'); bpy.ops.render.render(write_still=True)
else:
    bpy.ops.render.render(animation=True)
print('SW_RESULT ' + json.dumps({'blender': bpy.app.version_string, 'device': dev, 'gpus': dev_list, 'err': dev_err, 'frames': N}))
"""
BAAD_SCRIPT = """import bpy, os, json, math
P = json.load(open(os.path.join(os.getcwd(), 'params.json')))
FPS = 24; N = P['seconds'] * FPS
bpy.ops.wm.read_factory_settings(use_empty=True)
sc = bpy.context.scene
sc.render.fps = FPS; sc.frame_start = 1; sc.frame_end = N
sc.render.resolution_x, sc.render.resolution_y = P['w'], P['h']; sc.render.resolution_percentage = 100
sc.render.engine = 'CYCLES'; sc.cycles.samples = P['samples']; sc.cycles.use_denoising = True
try: sc.cycles.denoiser = 'OPENIMAGEDENOISE'
except Exception: pass
sc.render.image_settings.file_format = 'PNG'
sc.render.filepath = os.path.join(os.getcwd(), 'frames', '')
dev = 'CPU'; dev_err = ''; dev_list = []
try:
    pr = bpy.context.preferences.addons['cycles'].preferences
    for t in ('OPTIX', 'CUDA'):
        pr.compute_device_type = t; pr.get_devices()
        g = [d for d in pr.devices if d.type == t]
        if g:
            for d in pr.devices: d.use = (d.type == t)
            sc.cycles.device = 'GPU'; dev = t; dev_list = [d.name for d in g]
            if t == 'OPTIX':
                try: sc.cycles.denoiser = 'OPTIX'
                except Exception: pass
            break
    if dev == 'CPU': dev_err = 'no gpu devices: ' + ','.join(d.type + ':' + d.name for d in pr.devices)[:150]
except Exception as e:
    dev = 'CPU'; dev_err = str(e)[:150]
print('SW_DEVICE ' + dev + ' ' + str(dev_list) + ' ' + dev_err, flush=True)
if dev == 'CPU' and not P.get('allow_cpu_dev'): raise SystemExit(3)
def principled(name, color, rough=0.5, metal=0.0):
    m = bpy.data.materials.new(name); m.use_nodes = True; b = m.node_tree.nodes['Principled BSDF']
    b.inputs['Base Color'].default_value = color; b.inputs['Roughness'].default_value = rough; b.inputs['Metallic'].default_value = metal
    return m
def emit_mat(name, color, strength):
    m = bpy.data.materials.new(name); m.use_nodes = True; nt = m.node_tree; nt.nodes.clear()
    e = nt.nodes.new('ShaderNodeEmission'); e.inputs['Color'].default_value = color; e.inputs['Strength'].default_value = strength
    o = nt.nodes.new('ShaderNodeOutputMaterial'); nt.links.new(e.outputs[0], o.inputs['Surface']); return m
# pitch: striped grass via brick/checker-like wave texture
bpy.ops.mesh.primitive_plane_add(size=120, location=(0, 0, 0))
pitch = bpy.context.active_object
pm = bpy.data.materials.new('grass'); pm.use_nodes = True; nt = pm.node_tree; b = nt.nodes['Principled BSDF']; b.inputs['Roughness'].default_value = 0.85
wv = nt.nodes.new('ShaderNodeTexWave'); wv.wave_type = 'BANDS'; wv.bands_direction = 'Y'; wv.inputs['Scale'].default_value = 0.35; wv.inputs['Distortion'].default_value = 0.0
tc = nt.nodes.new('ShaderNodeTexCoord'); nt.links.new(tc.outputs['Object'], wv.inputs['Vector'])
cr = nt.nodes.new('ShaderNodeValToRGB'); cr.color_ramp.interpolation = 'CONSTANT'; cr.color_ramp.elements[0].color = (0.03, 0.26, 0.05, 1); cr.color_ramp.elements[1].color = (0.05, 0.36, 0.07, 1); cr.color_ramp.elements[1].position = 0.5
nt.links.new(wv.outputs['Fac'], cr.inputs['Fac']); nt.links.new(cr.outputs['Color'], b.inputs['Base Color'])
pitch.data.materials.append(pm)
# white lines (thin emissive-less white planes)
def line(x0, y0, x1, y1, w=0.18):
    cx, cy = (x0 + x1) / 2, (y0 + y1) / 2; ln = math.hypot(x1 - x0, y1 - y0)
    bpy.ops.mesh.primitive_plane_add(size=1, location=(cx, cy, 0.01)); o = bpy.context.active_object
    o.scale = (ln, w, 1); o.rotation_euler[2] = math.atan2(y1 - y0, x1 - x0); o.data.materials.append(principled('line', (0.9, 0.9, 0.9, 1), 0.6))
line(-9, 0, 9, 0)
bpy.ops.mesh.primitive_torus_add(major_radius=3.2, minor_radius=0.09, major_segments=96, minor_segments=8, location=(0, 0, 0.02))
c = bpy.context.active_object; c.scale[2] = 0.2; c.data.materials.append(principled('line', (0.9, 0.9, 0.9, 1), 0.6))
line(-9, -14, -9, 14); line(9, -14, 9, 14); line(-9, 14, 9, 14); line(-9, -14, 9, -14)
# ball with voronoi patches
bpy.ops.mesh.primitive_uv_sphere_add(radius=0.5, segments=64, ring_count=32, location=(0, -6, 0.5)); ball = bpy.context.active_object; bpy.ops.object.shade_smooth()
bm = bpy.data.materials.new('ball'); bm.use_nodes = True; nt = bm.node_tree; b = nt.nodes['Principled BSDF']; b.inputs['Roughness'].default_value = 0.3
vo = nt.nodes.new('ShaderNodeTexVoronoi'); vo.feature = 'DISTANCE_TO_EDGE'; vo.inputs['Scale'].default_value = 3.2
tc2 = nt.nodes.new('ShaderNodeTexCoord'); nt.links.new(tc2.outputs['Object'], vo.inputs['Vector'])
rp = nt.nodes.new('ShaderNodeValToRGB'); rp.color_ramp.interpolation = 'CONSTANT'; rp.color_ramp.elements[0].color = (0.02, 0.02, 0.02, 1); rp.color_ramp.elements[1].color = (0.95, 0.95, 0.95, 1); rp.color_ramp.elements[1].position = 0.045
nt.links.new(vo.outputs['Distance'], rp.inputs['Fac']); nt.links.new(rp.outputs['Color'], b.inputs['Base Color'])
ball.data.materials.append(bm)
bpy.context.preferences.edit.keyframe_new_interpolation_type = 'LINEAR'
# ball path: bounces toward camera-left goal line, spinning
import random
for f in range(1, N + 2, 2):
    t = (f - 1) / N
    ball.location = (math.sin(t * 5.0) * 2.2, -6 + t * 11.0, 0.5 + abs(math.sin(t * math.pi * 6)) * 2.2 * (1 - 0.5 * t))
    ball.rotation_euler = (t * 24, t * 9, 0)
    ball.keyframe_insert('location', frame=f); ball.keyframe_insert('rotation_euler', frame=f)
# camera: low, follows behind
cd = bpy.data.cameras.new('cam'); cd.lens = 35; cd.dof.use_dof = True; cd.dof.focus_object = ball; cd.dof.aperture_fstop = 2.4
cam = bpy.data.objects.new('cam', cd); sc.collection.objects.link(cam); sc.camera = cam
tg = bpy.data.objects.new('tg', None); sc.collection.objects.link(tg)
tk = cam.constraints.new('TRACK_TO'); tk.target = tg; tk.track_axis = 'TRACK_NEGATIVE_Z'; tk.up_axis = 'UP_Y'
for f in range(1, N + 2, 4):
    t = (f - 1) / N
    cam.location = (-3.0 + t * 2.6, -10 + t * 7.0, 2.6 + t * 0.4); cam.keyframe_insert('location', frame=f)
    tg.location = (math.sin(t * 5.0) * 1.8, -6 + t * 11.0 + 2.0, 0.9); tg.keyframe_insert('location', frame=f)
kl = bpy.data.lights.new('bk', 'POINT'); kl.energy = 350; kl.color = (1.0, 0.9, 0.75); kl.shadow_soft_size = 0.6
ko = bpy.data.objects.new('bk', kl); sc.collection.objects.link(ko); ko.parent = ball; ko.location = (0.0, -1.6, 1.8)
# floodlights: glowing emissive panels + real lights
def flood(x, y, z):
    l = bpy.data.lights.new('fl', 'AREA'); l.energy = 16000; l.size = 3; l.color = (1.0, 0.93, 0.8)
    lo = bpy.data.objects.new('fl', l); sc.collection.objects.link(lo); lo.location = (x, y, z - 0.5); lo.rotation_euler = (math.radians(25), 0, 0)
flood(-14, 24, 12); flood(14, 24, 12); flood(0, 28, 14)
w = bpy.data.worlds.new('w'); sc.world = w; w.use_nodes = True
w.node_tree.nodes['Background'].inputs['Color'].default_value = (0.02, 0.035, 0.09, 1); w.node_tree.nodes['Background'].inputs['Strength'].default_value = 1.0
try: sc.view_settings.view_transform = 'AgX'
except Exception: pass
if P.get('still'):
    sc.frame_set(P['still']); sc.render.filepath = os.path.join(os.getcwd(), 'still.png'); bpy.ops.render.render(write_still=True)
else:
    bpy.ops.render.render(animation=True)
print('SW_RESULT ' + json.dumps({'blender': bpy.app.version_string, 'device': dev, 'gpus': dev_list, 'err': dev_err, 'frames': N}))
"""
VIDEO_SCRIPT = """import bpy, os, json, math
P = json.load(open(os.path.join(os.getcwd(), 'params.json')))
FPS = 24; N = P['seconds'] * FPS
bpy.ops.wm.read_factory_settings(use_empty=True)
sc = bpy.context.scene
sc.render.fps = FPS; sc.frame_start = 1; sc.frame_end = N
sc.render.resolution_x, sc.render.resolution_y = P['w'], P['h']; sc.render.resolution_percentage = 100
sc.render.engine = 'CYCLES'; sc.cycles.samples = P['samples']; sc.cycles.use_denoising = True
try: sc.cycles.denoiser = 'OPENIMAGEDENOISE'
except Exception: pass
sc.render.image_settings.file_format = 'PNG'
sc.render.filepath = os.path.join(os.getcwd(), 'frames', '')
dev = 'CPU'; dev_err = ''; dev_list = []
try:
    pr = bpy.context.preferences.addons['cycles'].preferences
    for t in ('OPTIX', 'CUDA'):
        pr.compute_device_type = t; pr.get_devices()
        g = [d for d in pr.devices if d.type == t]
        if g:
            for d in pr.devices: d.use = (d.type == t)
            sc.cycles.device = 'GPU'; dev = t; dev_list = [d.name for d in g]
            if t == 'OPTIX':
                try: sc.cycles.denoiser = 'OPTIX'
                except Exception: pass
            break
    if dev == 'CPU': dev_err = 'no gpu devices: ' + ','.join(d.type + ':' + d.name for d in pr.devices)[:150]
except Exception as e:
    dev = 'CPU'; dev_err = str(e)[:150]
print('SW_DEVICE ' + dev + ' ' + str(dev_list) + ' ' + dev_err, flush=True)
if dev == 'CPU': raise SystemExit(3)
def mat(name, color, metal, rough, emit=0.0):
    m = bpy.data.materials.new(name); m.use_nodes = True
    b = m.node_tree.nodes['Principled BSDF']
    b.inputs['Base Color'].default_value = color; b.inputs['Metallic'].default_value = metal; b.inputs['Roughness'].default_value = rough
    if emit > 0:
        b.inputs['Emission Color'].default_value = color; b.inputs['Emission Strength'].default_value = emit
    return m
w = bpy.data.worlds.new('w'); sc.world = w; w.use_nodes = True
bg = w.node_tree.nodes['Background']; bg.inputs['Color'].default_value = (0.004, 0.008, 0.02, 1); bg.inputs['Strength'].default_value = 1.0
bpy.ops.mesh.primitive_plane_add(size=60, location=(0, 0, -2.2))
fl = bpy.context.active_object; fl.data.materials.append(mat('floor', (0.02, 0.025, 0.04, 1), 0.0, 0.12))
bpy.ops.mesh.primitive_uv_sphere_add(radius=0.9, segments=64, ring_count=32, location=(0, 0, 0))
sp = bpy.context.active_object; bpy.ops.object.shade_smooth(); sp.data.materials.append(mat('core', (1.0, 0.2, 0.0, 1), 0.0, 0.3, 4.0))

def halo(r, strength):
    bpy.ops.mesh.primitive_uv_sphere_add(radius=r, segments=48, ring_count=24, location=(0, 0, 0))
    h = bpy.context.active_object; bpy.ops.object.shade_smooth()
    hm = bpy.data.materials.new('halo'); hm.use_nodes = True; nt = hm.node_tree; nt.nodes.clear()
    lw = nt.nodes.new('ShaderNodeLayerWeight'); lw.inputs['Blend'].default_value = 0.5
    inv = nt.nodes.new('ShaderNodeMath'); inv.operation = 'SUBTRACT'; inv.inputs[0].default_value = 1.0
    nt.links.new(lw.outputs['Facing'], inv.inputs[1])
    rp = nt.nodes.new('ShaderNodeMath'); rp.operation = 'POWER'; rp.inputs[1].default_value = 2.0
    nt.links.new(inv.outputs[0], rp.inputs[0])
    ml = nt.nodes.new('ShaderNodeMath'); ml.operation = 'MULTIPLY'; ml.inputs[1].default_value = strength
    nt.links.new(rp.outputs[0], ml.inputs[0])
    em_ = nt.nodes.new('ShaderNodeEmission'); em_.inputs['Color'].default_value = (1.0, 0.18, 0.01, 1)
    nt.links.new(ml.outputs[0], em_.inputs['Strength'])
    tr = nt.nodes.new('ShaderNodeBsdfTransparent'); ad = nt.nodes.new('ShaderNodeAddShader'); out = nt.nodes.new('ShaderNodeOutputMaterial')
    nt.links.new(tr.outputs[0], ad.inputs[0]); nt.links.new(em_.outputs[0], ad.inputs[1]); nt.links.new(ad.outputs[0], out.inputs['Surface'])
    h.data.materials.append(hm); h.visible_shadow = False
    return h
halo(1.1, 0.45); halo(1.6, 0.45); halo(2.5, 0.18)
cm_ = sp.data.materials[0]; cnt = cm_.node_tree; cnt.nodes.clear()
ce = cnt.nodes.new('ShaderNodeEmission'); ce.inputs['Color'].default_value = (1.0, 0.2, 0.01, 1); ce.inputs['Strength'].default_value = 1.5
co_ = cnt.nodes.new('ShaderNodeOutputMaterial'); cnt.links.new(ce.outputs[0], co_.inputs['Surface'])
rings = []
specs = [(1.7, 0.06, (1.0, 0.78, 0.35, 1), 0.18, (1, 0, 0), 1), (2.4, 0.075, (0.85, 0.88, 0.95, 1), 0.12, (0, 1, 0), -1), (3.2, 0.09, (0.9, 0.45, 0.3, 1), 0.22, (1, 1, 0), 1)]
for i, (R, r, col, rough, ax, d) in enumerate(specs):
    bpy.ops.mesh.primitive_torus_add(major_radius=R, minor_radius=r, major_segments=128, minor_segments=24)
    o = bpy.context.active_object; bpy.ops.object.shade_smooth(); o.data.materials.append(mat('ring%d' % i, col, 1.0, rough))
    o.rotation_euler = (math.radians(70 + 20 * i), math.radians(15 * i), 0)
    rings.append((o, d, [1, 1, 2][i]))
bpy.context.preferences.edit.keyframe_new_interpolation_type = 'LINEAR'
for o, d, k in rings:
    o.keyframe_insert('rotation_euler', frame=1)
    o.rotation_euler[2] += d * 2 * math.pi * k
    o.keyframe_insert('rotation_euler', frame=N + 1)
em = bpy.data.objects.new('pivot', None); sc.collection.objects.link(em)
cd = bpy.data.cameras.new('cam'); cd.lens = 42; cd.dof.use_dof = True; cd.dof.focus_object = sp; cd.dof.aperture_fstop = 3.2
cam = bpy.data.objects.new('cam', cd); sc.collection.objects.link(cam); cam.parent = em; cam.location = (0, -9.5, 2.6); sc.camera = cam
tc = cam.constraints.new('TRACK_TO'); tc.target = sp; tc.track_axis = 'TRACK_NEGATIVE_Z'; tc.up_axis = 'UP_Y'
em.rotation_euler = (0, 0, math.radians(-25)); em.keyframe_insert('rotation_euler', frame=1)
em.rotation_euler = (0, 0, math.radians(25)); em.keyframe_insert('rotation_euler', frame=N + 1)
def area(name, loc, energy, color, size):
    l = bpy.data.lights.new(name, 'AREA'); l.energy = energy; l.color = color; l.size = size
    o = bpy.data.objects.new(name, l); sc.collection.objects.link(o); o.location = loc
    c = o.constraints.new('TRACK_TO'); c.target = sp; c.track_axis = 'TRACK_NEGATIVE_Z'; c.up_axis = 'UP_Y'
area('key', (-5, -5, 5), 900, (1.0, 0.9, 0.8), 4)
area('rim', (6, 4, 3), 700, (0.35, 0.55, 1.0), 5)
pl = bpy.data.lights.new('glow', 'POINT'); pl.energy = 4500; pl.color = (1.0, 0.5, 0.15); pl.shadow_soft_size = 0.5
po = bpy.data.objects.new('glow', pl); sc.collection.objects.link(po)
try: sc.view_settings.view_transform = 'AgX'
except Exception: pass

try:
    sc.use_nodes = True
    ntc = sc.node_tree
    for n_ in list(ntc.nodes): ntc.nodes.remove(n_)
    rl = ntc.nodes.new('CompositorNodeRLayers'); gl = ntc.nodes.new('CompositorNodeGlare'); co = ntc.nodes.new('CompositorNodeComposite')
    gl.glare_type = 'FOG_GLOW'; gl.quality = 'MEDIUM'
    try: gl.threshold = 0.8; gl.size = 7
    except Exception: pass
    ntc.links.new(rl.outputs['Image'], gl.inputs['Image']); ntc.links.new(gl.outputs['Image'], co.inputs['Image'])
except Exception as e:
    print('SW_NOGLARE ' + str(e)[:80])
bpy.ops.render.render(animation=True)
print('SW_RESULT ' + json.dumps({'blender': bpy.app.version_string, 'device': dev, 'gpus': dev_list, 'err': dev_err, 'frames': N}))
"""

def blender_video(root, jd, payload):
    """Fixed job: preset name + seconds + resolution only (all validated). Renders a PNG sequence in the job folder with a FIXED script, encodes with ffmpeg (NVENC, falls back to libx264), returns the MP4 as the single result file."""
    preset = payload.get("preset", "orbit_rings"); secs = payload.get("seconds", 6); res = payload.get("res", "540p")
    if preset not in VIDEO_PRESETS or not isinstance(secs, int) or isinstance(secs, bool) or not (1 <= secs <= 12) or res not in VIDEO_RES:
        return {"ok": False, "error": "invalid parameters (preset/seconds 1-12/res)"}
    exe = find_blender(root); ff = find_ffmpeg(root)
    if not exe: return {"ok": False, "error": "Blender not found on this PC"}
    if not ff: return {"ok": False, "error": "ffmpeg not found"}
    w, h = VIDEO_RES[res]; samples = int(payload.get("samples", 48)) if isinstance(payload.get("samples", 48), int) and 4 <= payload.get("samples", 48) <= 128 else 48
    pathlib.Path(jd, "frames").mkdir(exist_ok=True)
    prm = {"seconds": secs, "w": w, "h": h, "samples": samples}
    if preset == "atlas_map":
        import zlib
        geo = json.loads(zlib.decompress(base64.b64decode(ATLAS_GEO_Z)).decode()); known = {g[0] for g in geo}
        cs = payload.get("countries", ["EGY"])
        if not isinstance(cs, list) or not (1 <= len(cs) <= 6) or not all(isinstance(c, str) and re.fullmatch(r"[A-Z]{3}", c) and c in known for c in cs):
            return {"ok": False, "error": "invalid countries (1-6 ISO3 codes)"}
        prm["countries"] = cs; pathlib.Path(jd, "geo.json").write_text(json.dumps(geo))
    pathlib.Path(jd, "params.json").write_text(json.dumps(prm))
    pathlib.Path(jd, "scene.py").write_text(ATLAS_SCRIPT if preset == "atlas_map" else BAAD_SCRIPT if preset == "baad_style" else VIDEO_SCRIPT)
    pw0 = power_state(); t0 = time.time(); util = []; stop = threading.Event()
    def _samp():
        while not stop.wait(5):
            try:
                v = subprocess.run(["nvidia-smi", "--query-gpu=utilization.gpu", "--format=csv,noheader,nounits"], capture_output=True, text=True, timeout=6).stdout.strip().splitlines()[0]
                util.append(int(v))
            except Exception: pass
    th = threading.Thread(target=_samp, daemon=True); th.start()
    try: r = subprocess.run([exe, "-b", "--factory-startup", "--offline-mode", "-noaudio", "--python", str(pathlib.Path(jd, "scene.py"))], capture_output=True, text=True, timeout=1800, cwd=str(jd))
    except subprocess.TimeoutExpired:
        stop.set(); return {"ok": False, "error": "blender timed out (30 min), killed"}
    stop.set(); render_sec = round(time.time() - t0, 1); info = ""; devline = ""
    for line in r.stdout.splitlines():
        if line.startswith("SW_RESULT "): info = line[10:][:300]
        if line.startswith("SW_DEVICE "): devline = line[10:][:240]
    gu = {"samples": len(util), "avg": round(sum(util) / len(util), 1) if util else None, "max": max(util) if util else None}
    nfr = len(list(pathlib.Path(jd, "frames").glob("*.png")))
    if r.returncode != 0 or nfr != secs * 24: return {"ok": False, "render_sec": render_sec, "frames": nfr, "error": "blender failed rc=%s: %s" % (r.returncode, ((r.stderr or "") + (r.stdout or ""))[-400:])}
    out = pathlib.Path(jd, "out.mp4"); enc = None
    for codec, extra in (("h264_nvenc", ["-preset", "p5", "-cq", "21"]), ("libx264", ["-preset", "medium", "-crf", "18"])):
        cmd = [ff, "-hide_banner", "-loglevel", "error", "-y", "-protocol_whitelist", "file", "-framerate", "24", "-i", str(pathlib.Path(jd, "frames", "%04d.png")), "-c:v", codec] + extra + ["-pix_fmt", "yuv420p", "-movflags", "+faststart", str(out)]
        e = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=str(jd))
        if e.returncode == 0 and out.exists(): enc = codec; break
    if not enc: return {"ok": False, "render_sec": render_sec, "error": "ffmpeg encode failed: " + (e.stderr or "")[:300]}
    data = out.read_bytes()
    return {"ok": True, "render_sec": render_sec, "encoder": enc, "frames": nfr, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "info": info, "device_line": devline, "gpu_util": gu, "power_start": pw0, "power_end": power_state(), "_art": ("out.mp4", data)}

_rs_cache = {"t": 0, "v": False}
def resolve_info():
    """Read-only detection of DaVinci Resolve (fixed Program Files path). Returns 'path | version' or False. Cached 10 min. Runs no Resolve code."""
    if time.time() - _rs_cache["t"] < 600: return _rs_cache["v"]
    _rs_cache["t"] = time.time(); _rs_cache["v"] = False
    for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramW6432")):
        if not base: continue
        p = pathlib.Path(base, "Blackmagic Design", "DaVinci Resolve", "Resolve.exe")
        if p.exists():
            ver = "?"
            try:
                ver = subprocess.run(["powershell", "-NoProfile", "-Command", "(Get-Item -LiteralPath '%s').VersionInfo.ProductVersion" % str(p).replace("'", "")], capture_output=True, text=True, timeout=20).stdout.strip()[:40] or "?"
            except Exception: pass
            _rs_cache["v"] = str(p) + " | " + ver; break
    return _rs_cache["v"]

def power_state():
    """Read-only: AC/battery via GetSystemPowerStatus (no subprocess)."""
    try:
        import ctypes
        class S(ctypes.Structure): _fields_ = [("ac", ctypes.c_ubyte), ("flag", ctypes.c_ubyte), ("pct", ctypes.c_ubyte), ("sf", ctypes.c_ubyte), ("lt", ctypes.c_uint32), ("lf", ctypes.c_uint32)]
        st = S(); ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(st))
        return ("AC" if st.ac == 1 else "battery" if st.ac == 0 else "?") + " " + (str(st.pct) + "%" if st.pct <= 100 else "?")
    except Exception: return "n/a"

def gpu_info():
    try:
        return subprocess.run(["nvidia-smi", "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader"], capture_output=True, text=True, timeout=8).stdout.strip() or "none"
    except Exception: return "none"

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--enroll"); ap.add_argument("--run", action="store_true"); ap.add_argument("--bot", required=True); ap.add_argument("--root", required=True); ap.add_argument("--supervised", action="store_true")
    a = ap.parse_args(); os.makedirs(a.root, exist_ok=True)
    if a.enroll: enroll(a)
    elif a.run: loop(a)
