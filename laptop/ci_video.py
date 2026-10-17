import os, sys, json, pathlib, time
root = os.environ["SW_ROOT"]; out = pathlib.Path(os.environ["SW_OUT"]); sys.path.insert(0, root)
import worker
jd = pathlib.Path(root, "jobs", "v"); jd.mkdir(parents=True, exist_ok=True)
t = time.time()
r = worker.blender_video(root, jd, {"preset": "orbit_rings", "seconds": int(os.environ["SW_SECS"]), "res": os.environ["SW_RES"], "samples": int(os.environ["SW_SAMPLES"])})
art = r.pop("_art", None); print(json.dumps(r)[:900]); print("total sec", round(time.time() - t, 1))
if art: (out / "out.mp4").write_bytes(art[1])
fr = sorted(pathlib.Path(jd, "frames").glob("*.png"))
for i in (0, len(fr) // 2, len(fr) - 1):
    if fr: (out / ("frame_%d.png" % i)).write_bytes(fr[i].read_bytes())
# invalid params must be refused
print("bad preset:", worker.blender_video(root, jd, {"preset": "x"}))
print("bad seconds:", worker.blender_video(root, jd, {"seconds": 999}))
print("bad res:", worker.blender_video(root, jd, {"res": "4k"}))
sys.exit(0 if r.get("ok") else 1)
