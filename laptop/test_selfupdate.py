"""Self-update tests against a local HTTP server. Uses a THROWAWAY key (never the release key) by passing pub_hex to check_update."""
import os, sys, json, shutil, tempfile, threading, http.server, functools, hashlib, time, subprocess, pathlib
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import worker
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as S
tmp = tempfile.mkdtemp(); results = []
def check(name, cond): results.append((name, bool(cond))); print(("PASS " if cond else "FAIL ") + name)
key = Ed25519PrivateKey.generate(); other = Ed25519PrivateKey.generate()
pub = key.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw).hex()
rel = pathlib.Path(tmp, "rel"); root = pathlib.Path(tmp, "root"); root.mkdir()
(root / "worker.py").write_text("print('old')\n"); (root / "ed25519_verify.py").write_text("# old\n")
def build(seq, files, exp_delta=3600, signer=key, mutate=None, sizes=None):
    shutil.rmtree(rel, ignore_errors=True); (rel / "files").mkdir(parents=True); fl = []
    for n, b in files.items():
        if "/" not in n and ".." not in n: (rel / "files" / n).write_bytes(b)
        fl.append({"name": n, "sha256": hashlib.sha256(b).hexdigest(), "size": (sizes or {}).get(n, len(b))})
    m = json.dumps({"sequence": seq, "issued": int(time.time()), "expires": int(time.time()) + exp_delta, "files": fl}, sort_keys=True, separators=(",", ":")).encode()
    sig = signer.sign(m).hex()
    if mutate == "manifest": m = m.replace(b'"sequence":%d' % seq, b'"sequence":%d' % (seq + 5))
    (rel / "manifest.json").write_bytes(m); (rel / "manifest.sig").write_text(sig)
def fetch(path):
    p = rel / path.replace("/worker/release/", ""); return p.read_bytes()
def run(): return worker.check_update(str(root), "http://unused", pub_hex=pub, fetch=fetch)
good = b"print('new v')\n"
# 1 tampered manifest (valid sig for the original, content altered)
build(5, {"worker.py": good}, mutate="manifest"); st, d = run(); check("tampered manifest refused (%s)" % d, st == "refused" and (root / "worker.py").read_text() == "print('old')\n")
# 2 signature by another key
build(5, {"worker.py": good}, signer=other); st, d = run(); check("wrong-key signature refused (%s)" % d, st == "refused")
# 3 expired
build(5, {"worker.py": good}, exp_delta=-10); st, d = run(); check("expired manifest refused (%s)" % d, st == "refused")
# 4 bad file hash (file changed after signing)
build(5, {"worker.py": good}); (rel / "files" / "worker.py").write_bytes(b"print('evil')\n   \n"); st, d = run(); check("bad hash/size refused (%s)" % d, st == "refused" and (root / "worker.py").read_text() == "print('old')\n")
# 4b same size, different bytes
build(5, {"worker.py": good}); (rel / "files" / "worker.py").write_bytes(b"print('evil')\n"[:len(good)].ljust(len(good), b" ")); st, d = run(); check("same-size different bytes refused (%s)" % d, st == "refused")
# 5 path traversal / not allow-listed names
for bad in ["../evil.py", "evil.py", "launcher.py", "worker.py/../x", "C:\\x.py"]:
    build(5, {bad: good}); st, d = run(); check("name %r refused (%s)" % (bad, d), st == "refused")
# 6 non-compiling code
build(5, {"worker.py": b"def (:\n"}); st, d = run(); check("non-compiling code refused (%s)" % d, st == "refused")
# 7 good update applies
build(5, {"worker.py": good}); st, d = run()
check("valid release applied (%s)" % d, st == "applied" and (root / "worker.py").read_bytes() == good and worker.current_seq(str(root)) == 5 and (root / "backup" / "worker.py").exists() and json.loads((root / "pending.json").read_text())["prev_seq"] == 0)
# 8 replay of same / older sequence
build(5, {"worker.py": b"print('replay')\n"}); st, d = run(); check("replay same seq not applied (%s)" % d, st == "current" and (root / "worker.py").read_bytes() == good)
build(3, {"worker.py": b"print('older')\n"}); st, d = run(); check("older seq not applied (%s)" % d, st == "current" and (root / "worker.py").read_bytes() == good)
# 9 rolled-back seq is not retried
(root / "bad_seqs.json").write_text("[6]"); build(6, {"worker.py": b"print('x')\n"}); st, d = run(); check("rolled-back seq refused (%s)" % d, st == "refused")
# 10 launcher rollback: new worker that never becomes healthy
(root / "pending.json").unlink()
(root / "worker.py").write_text("import time,sys\ntime.sleep(60)\n"); 
(root / "backup").mkdir(exist_ok=True); (root / "backup" / "worker.py").write_text("import sys,json,time,pathlib\nroot=sys.argv[sys.argv.index('--root')+1]\npathlib.Path(root,'healthy.json').write_text(json.dumps({'seq':0}))\nsys.exit(0)\n")
(root / "update_seq").write_text("7"); (root / "pending.json").write_text(json.dumps({"seq": 7, "prev_seq": 5, "files": ["worker.py"]}))
(root / "STOP").write_text("")  # stop after first loop pass
# launcher checks STOP at loop top; remove it before and create it after rollback via a helper thread
(root / "STOP").unlink()
def stopper():
    for _ in range(40):
        time.sleep(0.5)
        if "ROLLED BACK" in (root / "worker.log").read_text() if (root / "worker.log").exists() else False:
            (root / "STOP").write_text(""); return
threading.Thread(target=stopper, daemon=True).start()
r = subprocess.run([sys.executable, os.path.join(HERE, "launcher.py"), "--bot", "http://x", "--root", str(root), "--health-wait", "4"], capture_output=True, text=True, timeout=60)
log = (root / "worker.log").read_text()
check("launcher rolled back unhealthy release", "ROLLED BACK release 7" in log and "time.sleep(60)" not in (root / "worker.py").read_text() and worker.current_seq(str(root)) == 5 and 7 in json.loads((root / "bad_seqs.json").read_text()) and not (root / "pending.json").exists())
print("RESULT", "PASS" if all(c for _, c in results) else "FAIL", sum(c for _, c in results), "/", len(results))
sys.exit(0 if all(c for _, c in results) else 1)
