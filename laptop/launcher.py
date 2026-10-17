"""ShaherWorker launcher. Tiny, stdlib only, NOT self-updating. Runs worker.py, restarts it after a signed update,
and restores the previous files if a new release does not report healthy within 90 s.
Usage: launcher.py --bot URL --root DIR"""
import argparse, json, os, pathlib, shutil, subprocess, sys, time
RESTART_CODE = 75
HEALTH_WAIT = 90

def log(root, msg):
    with open(pathlib.Path(root, "worker.log"), "a", encoding="utf-8") as f: f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + "[launcher] " + msg + "\n")

def rj(p, d):
    try: return json.loads(pathlib.Path(p).read_text())
    except Exception: return d

def rollback(root, pend):
    r = pathlib.Path(root); bk = r / "backup"
    for name in pend.get("files", []):
        if (bk / name).exists(): shutil.copy2(bk / name, r / name)
        else: (r / name).unlink(missing_ok=True)
    prev = int(pend["seq"]) - 0
    bad = rj(r / "bad_seqs.json", []); bad.append(prev); (r / "bad_seqs.json").write_text(json.dumps(bad))
    (r / "update_seq").write_text(str(pend.get("prev_seq", 0)))
    (r / "pending.json").unlink(missing_ok=True)
    log(root, "ROLLED BACK release %s (not healthy in %ds)" % (pend["seq"], HEALTH_WAIT))

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--bot", required=True); ap.add_argument("--root", required=True)
    ap.add_argument("--health-wait", type=int, default=HEALTH_WAIT); a = ap.parse_args()
    root = a.root; stop = pathlib.Path(root, "STOP")
    while not stop.exists():
        pend = rj(pathlib.Path(root, "pending.json"), None)
        p = subprocess.Popen([sys.executable, str(pathlib.Path(root, "worker.py")), "--run", "--supervised", "--bot", a.bot, "--root", root])
        if pend:
            t0 = time.time(); ok = False
            while time.time() - t0 < a.health_wait and p.poll() is None:
                if rj(pathlib.Path(root, "healthy.json"), {}).get("seq") == pend["seq"]: ok = True; break
                time.sleep(1)
            if ok: pathlib.Path(root, "pending.json").unlink(missing_ok=True); log(root, "release %s healthy" % pend["seq"])
            else:
                if p.poll() is None: p.kill(); p.wait()
                rollback(root, pend); continue
        code = p.wait()
        log(root, "worker exited code %s" % code)
        if code == RESTART_CODE: continue
        if stop.exists(): break
        time.sleep(15)

if __name__ == "__main__": main()
