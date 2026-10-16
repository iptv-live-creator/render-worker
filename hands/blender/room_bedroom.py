# Modern bedroom, built procedurally. Optional Poly Haven CC0 HDRI and floor texture (ids validated by the worker, hosts allowlisted).
import bpy, sys, json, math, os, re, urllib.request
from mathutils import Vector
a = sys.argv[sys.argv.index("--") + 1:]; spec = json.load(open(a[0])); outdir = a[1]
os.makedirs(outdir, exist_ok=True)
ASSETS = []
def ph_file(kind, aid, res="1k"):
    """download one Poly Haven file into the job folder; returns path or None. Only api.polyhaven.com and dl.polyhaven.org."""
    if not re.match(r"^[a-z0-9_]{2,50}$", aid or ""): return None
    try:
        info = json.load(urllib.request.urlopen(urllib.request.Request("https://api.polyhaven.com/files/" + aid, headers={"User-Agent": "atlas-hands/1.0"}), timeout=30))
        if kind == "hdri": u = info["hdri"][res]["hdr"]["url"]
        else: u = info["Diffuse"][res]["jpg"]["url"]
        if not re.match(r"^https://dl\.polyhaven\.org/", u): return None
        p = os.path.join(os.path.dirname(a[0]), aid + os.path.splitext(u)[1])
        req = urllib.request.Request(u, headers={"User-Agent": "atlas-hands/1.0"}); open(p, "wb").write(urllib.request.urlopen(req, timeout=60).read())
        ASSETS.append({"id": aid, "kind": kind, "license": "CC0", "source": "https://polyhaven.com/a/" + aid}); return p
    except Exception as e:
        print("polyhaven skip", aid, str(e)[:80]); return None

def ph_model(aid, x, y, rz):
    """import one Poly Haven CC0 glTF model (1k) at floor position (x, y). Only api.polyhaven.com / dl.polyhaven.org."""
    if not re.match(r"^[a-z0-9_]{2,50}$", aid or ""): return False
    try:
        info = json.load(urllib.request.urlopen(urllib.request.Request("https://api.polyhaven.com/files/" + aid, headers={"User-Agent": "atlas-hands/1.0"}), timeout=30))
        g = info["gltf"]["1k"]["gltf"]; base = os.path.join(os.path.dirname(a[0]), "prop_" + aid); os.makedirs(base, exist_ok=True)
        todo = [(os.path.basename(g["url"]), g["url"])] + [(k, v["url"]) for k, v in g.get("include", {}).items()]
        for rel, u in todo:
            if not re.match(r"^https://dl\.polyhaven\.org/", u) or ".." in rel or rel.startswith("/"): return False
            p = os.path.join(base, rel); os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "wb").write(urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": "atlas-hands/1.0"}), timeout=60).read())
        before = set(bpy.data.objects); bpy.ops.import_scene.gltf(filepath=os.path.join(base, os.path.basename(g["url"])))
        for o in [o for o in bpy.data.objects if o not in before and o.parent is None]:
            o.location = (x, y, 0); o.rotation_euler[2] = math.radians(rz)
        ASSETS.append({"id": aid, "kind": "model", "license": "CC0", "source": "https://polyhaven.com/a/" + aid}); return True
    except Exception as e:
        print("polyhaven model skip", aid, str(e)[:100]); return False

bpy.ops.wm.read_factory_settings(use_empty=True)
sc = bpy.context.scene; W, Hh = spec["res"]; sc.render.resolution_x, sc.render.resolution_y = W, Hh
sc.render.engine = "CYCLES"; sc.cycles.samples = spec.get("samples", 24); sc.cycles.use_denoising = bool(spec.get("denoise"))
if spec.get("denoise"):
    try: sc.cycles.denoiser = "OPENIMAGEDENOISE"
    except Exception: pass
if spec.get("gpu"):
    try:
        pr = bpy.context.preferences.addons["cycles"].preferences
        for t in ("OPTIX", "CUDA"):
            try: pr.compute_device_type = t; pr.get_devices(); break
            except Exception: continue
        for d in pr.devices: d.use = True
        sc.cycles.device = "GPU"
    except Exception as e: print("gpu setup failed", e)
sc.render.image_settings.file_format = "PNG"; sc.frame_start = 1; sc.frame_end = spec["frames"]; sc.render.fps = 24
pal = {"warm": ((0.80, 0.74, 0.65), (0.30, 0.22, 0.16), (0.55, 0.60, 0.65)), "cool": ((0.72, 0.76, 0.80), (0.18, 0.22, 0.28), (0.85, 0.80, 0.70))}[spec.get("palette", "warm")]
def mat(name, col, rough=0.6, emit=None, strength=0):
    m = bpy.data.materials.new(name); m.use_nodes = True; b = m.node_tree.nodes["Principled BSDF"]
    b.inputs["Base Color"].default_value = (*col, 1); b.inputs["Roughness"].default_value = rough
    if emit: b.inputs["Emission Color"].default_value = (*emit, 1); b.inputs["Emission Strength"].default_value = strength
    return m
def box(name, loc, size, m):
    bpy.ops.mesh.primitive_cube_add(location=loc); o = bpy.context.object; o.name = name; o.scale = (size[0] / 2, size[1] / 2, size[2] / 2); o.data.materials.append(m); return o
RW, RD, RH = 5.0, 5.0, 2.8
PROPS = [p for p in spec.get("props", []) if isinstance(p, dict)][:6]
NS_MODEL = any("nightstand" in str(p.get("id")) for p in PROPS)
wall = mat("wall", pal[0], 0.9); floor_m = mat("floor", (0.45, 0.32, 0.2), 0.45); fabric = mat("fabric", pal[2], 0.95); wood = mat("wood", pal[1], 0.5)
bed_m = mat("bedding", (0.92, 0.92, 0.90), 0.95); lamp_m = mat("lamp", (1, 0.85, 0.6), 0.3, (1, 0.7, 0.4), 12); rug_m = mat("rug", (0.5, 0.5, 0.52), 1.0)
fp = ph_file("tex", spec.get("floor_tex"))
if fp:
    n = floor_m.node_tree.nodes; t = n.new("ShaderNodeTexImage"); t.image = bpy.data.images.load(fp); floor_m.node_tree.links.new(t.outputs["Color"], n["Principled BSDF"].inputs["Base Color"])
box("floor", (0, 0, -0.05), (RW, RD, 0.1), floor_m)
box("back", (0, RD / 2, RH / 2), (RW, 0.1, RH), wall); box("left", (-RW / 2, 0, RH / 2), (0.1, RD, RH), wall)
box("ceil", (0, 0, RH + 0.05), (RW, RD, 0.1), wall)
# right wall with window opening (two pieces + header + sill)
box("rw1", (RW / 2, -1.6, RH / 2), (0.1, 1.8, RH), wall); box("rw2", (RW / 2, 1.9, RH / 2), (0.1, 1.2, RH), wall)
box("rw_top", (RW / 2, 0.6, 2.45), (0.1, 1.4, 0.7), wall); box("rw_sill", (RW / 2, 0.6, 0.45), (0.1, 1.4, 0.9), wall)
# bed against back wall
box("bed_base", (0, RD / 2 - 1.1, 0.25), (1.8, 2.1, 0.5), wood); box("mattress", (0, RD / 2 - 1.1, 0.6), (1.7, 2.0, 0.25), bed_m)
box("headboard", (0, RD / 2 - 0.08, 0.85), (1.9, 0.08, 1.2), wood)
box("blanket", (0, RD / 2 - 1.5, 0.76), (1.72, 1.2, 0.08), fabric)
for x in (-0.45, 0.45): box("pillow", (x, RD / 2 - 0.35, 0.82), (0.7, 0.4, 0.16), bed_m)
for x in (-1.2, 1.2):
    if not NS_MODEL: box("nightstand", (x, RD / 2 - 0.3, 0.25), (0.45, 0.4, 0.5), wood)
    box("lamp", (x, RD / 2 - 0.3, 0.62), (0.18, 0.18, 0.24), lamp_m)
    pl = bpy.data.lights.new("pl", "POINT"); pl.energy = 60; pl.color = (1, 0.75, 0.5); po = bpy.data.objects.new("pl", pl); po.location = (x, RD / 2 - 0.3, 0.8); sc.collection.objects.link(po)
box("rug", (0, 0.4, 0.01), (2.6, 1.8, 0.02), rug_m)
box("art", (0, RD / 2 - 0.04, 1.9), (1.0, 0.04, 0.6), fabric)
box("wardrobe", (-RW / 2 + 0.35, -1.2, 1.1), (0.6, 1.6, 2.2), wood)
for p in PROPS:
    if not ph_model(str(p.get("id")), float(p.get("x", 0)), float(p.get("y", 0)), float(p.get("rz", 0))) and "nightstand" in str(p.get("id")): print("nightstand model failed")
# window light + world
sun = bpy.data.lights.new("sun", "AREA"); sun.energy = 400; sun.size = 1.4; so = bpy.data.objects.new("sun", sun); so.location = (RW / 2 + 0.4, 0.6, 1.6); so.rotation_euler = (0, math.radians(-90), 0); sc.collection.objects.link(so)
w = bpy.data.worlds.new("w"); sc.world = w; w.use_nodes = True; bg = w.node_tree.nodes["Background"]; bg.inputs[1].default_value = 0.6
hp = ph_file("hdri", spec.get("hdri"))
if hp:
    n = w.node_tree.nodes; e = n.new("ShaderNodeTexEnvironment"); e.image = bpy.data.images.load(hp); w.node_tree.links.new(e.outputs["Color"], bg.inputs["Color"])
else: bg.inputs[0].default_value = (0.6, 0.7, 0.9, 1)
cam = bpy.data.cameras.new("c"); cam.lens = 22; co = bpy.data.objects.new("c", cam); sc.collection.objects.link(co); sc.camera = co
n = spec["frames"]
for fr, (p0, p1) in ((1, ((1.9, -2.3, 1.45), (1.9, -2.3, 1.45))), (n, ((1.9, -2.3, 1.45), (0.6, -1.5, 1.35)))):
    sc.frame_set(fr); co.location = p1 if fr == n and n > 1 else p0
    tgt = Vector((0, RD / 2 - 1.2, 0.8)); d = tgt - co.location; co.rotation_euler = d.to_track_quat("-Z", "Y").to_euler(); co.keyframe_insert("location"); co.keyframe_insert("rotation_euler")
json.dump({"assets": ASSETS}, open(os.path.join(os.path.dirname(a[0]), "assets.json"), "w"))
sc.render.filepath = os.path.join(outdir, "f_")
if n == 1: sc.render.filepath = os.path.join(outdir, "f_0001.png"); bpy.ops.render.render(write_still=True)
else: bpy.ops.render.render(animation=True)
