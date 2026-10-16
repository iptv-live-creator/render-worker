import bpy, sys, json
a = sys.argv[sys.argv.index("--") + 1:]; spec = json.load(open(a[0])); out = a[1]
bpy.ops.wm.read_factory_settings(use_empty=True)
sc = bpy.context.scene; sc.render.engine = "BLENDER_EEVEE_NEXT" if hasattr(bpy.types, "RENDER_PT_eevee_next") else "BLENDER_EEVEE"
try: sc.render.engine = "BLENDER_WORKBENCH"
except Exception: pass
sc.render.resolution_x, sc.render.resolution_y = spec["res"]; sc.render.filepath = out; sc.render.image_settings.file_format = "PNG"
bpy.ops.object.text_add(location=(0, 0, 0)); t = bpy.context.object; t.data.body = spec["text"] or "Atlas"; t.data.extrude = 0.2; t.data.align_x = "CENTER"
cam = bpy.data.cameras.new("c"); co = bpy.data.objects.new("c", cam); sc.collection.objects.link(co); co.location = (0, -8, 0); co.rotation_euler = (1.5708, 0, 0); sc.camera = co
l = bpy.data.lights.new("l", "SUN"); lo = bpy.data.objects.new("l", l); sc.collection.objects.link(lo); lo.rotation_euler = (0.6, 0.2, 0.5)
bpy.ops.render.render(write_still=True)
