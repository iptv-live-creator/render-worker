import json,subprocess,sys,os,math,struct,wave,asyncio
H=os.path.dirname(os.path.abspath(__file__)); OUT=sys.argv[2] if len(sys.argv)>2 else '/tmp/hf/suez'
sc=json.load(open(sys.argv[1])); os.makedirs(OUT+'/assets',exist_ok=True)
VOICES={'n':('ar-EG-ShakirNeural','+0Hz'),'a':('ar-EG-ShakirNeural','+40Hz'),'b':('ar-EG-SalmaNeural','+0Hz'),'c':('ar-EG-ShakirNeural','-15Hz')}
SPK={'narrator':'n','n':'n','a':'a','b':'b','c':'c'}
import re as _re
for _s in sc['scenes']:
    if _re.search(r'[A-Za-z0-9]',_s.get('vo','')): raise SystemExit('lint: Latin/digit in voice line: '+_s['vo'][:60])
for _s in sc['scenes']: _s['spk']=SPK.get(str(_s.get('speaker','n')).lower(),'n')
FPS=15; GAP=0.35
# 1. voices
auds=[]
for i,s in enumerate(sc['scenes']):
    v,p=VOICES[s['spk']]; f=f'{OUT}/assets/s{i}.mp3'
    import re as _r2
    clean=_r2.sub(r'[^\u0600-\u06FF\s.,!?؟،:؛-]','',s['vo']).strip()
    for _t in range(9):
        if _t: __import__('time').sleep(min(12,2*_t))
        vv,pp,tx=v,p,s['vo']
        if _t>=7: vv='ar-EG-ShakirNeural'
        if _t>=2: pp='+0Hz'
        if _t>=3: tx=clean
        r=subprocess.run(['python3','-m','edge_tts','--voice',vv]+([] if pp=='+0Hz' else ['--pitch='+pp])+['--text',tx,'--write-media',f],capture_output=True,timeout=60)
        if r.returncode==0 and os.path.getsize(f)>1000: break
    else: raise SystemExit('tts failed: '+s['vo'][:80]+' | '+r.stderr.decode()[-200:])
    d=float(subprocess.check_output(['ffprobe','-v','error','-show_entries','format=duration','-of','csv=p=0',f]))
    auds.append((f,d))
# 2. master audio + envelope
t=0.0; starts=[]; cmd=['ffmpeg','-v','error','-y']; fl=[]
for i,(f,d) in enumerate(auds):
    starts.append(t); cmd+=['-i',f]; fl.append(f'[{i}:a]adelay={int(t*1000)}|{int(t*1000)},aresample=24000[a{i}]'); t+=d+GAP
total=t+0.4
fl.append(''.join(f'[a{i}]' for i in range(len(auds)))+f'amix=inputs={len(auds)}:normalize=0,apad=pad_dur=1[m]')
subprocess.run(cmd+['-filter_complex',';'.join(fl),'-map','[m]','-t',str(total),'-ac','1',OUT+'/assets/voice_dry.wav'],check=True)
# music pad (procedural, no library) + whoosh at each scene start, ducked under voice
wf=[f'sine=f=110:d={total:.2f}',f'sine=f=165:d={total:.2f}',f'sine=f=220:d={total:.2f}']
mc=['ffmpeg','-v','error','-y']
for x in wf: mc+=['-f','lavfi','-i',x]
for i in range(len(auds)): mc+=['-f','lavfi','-i','anoisesrc=d=0.9:c=pink:a=0.5']
mf=['[0][1][2]amix=inputs=3:normalize=0,volume=0.05,tremolo=f=0.15:d=0.4,aresample=24000[mus]']
for i,st in enumerate(starts): mf.append(f'[{3+i}]highpass=f=400,afade=t=in:d=0.4,afade=t=out:st=0.45:d=0.45,volume=0.35,adelay={max(0,int((st-0.5)*1000))}|{max(0,int((st-0.5)*1000))},aresample=24000[w{i}]')
mf.append('[mus]'+''.join(f'[w{i}]' for i in range(len(auds)))+f'amix=inputs={1+len(auds)}:normalize=0[bed]')
subprocess.run(mc+['-filter_complex',';'.join(mf),'-map','[bed]','-t',str(total),'-ac','1',OUT+'/assets/bed.wav'],check=True)
subprocess.run(['ffmpeg','-v','error','-y','-i',OUT+'/assets/voice_dry.wav','-i',OUT+'/assets/bed.wav','-filter_complex','[0]asplit=2[v1][v2];[1]anull[b];[b][v1]sidechaincompress=threshold=0.02:ratio=6[bd];[v2][bd]amix=inputs=2:normalize=0,alimiter=limit=0.95[o]','-map','[o]','-ac','1',OUT+'/assets/voice.wav'],check=True)
os.replace(OUT+'/assets/voice_dry.wav',OUT+'/assets/voice_dry_.wav')
w=wave.open(OUT+'/assets/voice_dry_.wav'); n=w.getnframes(); raw=w.readframes(n); sr=w.getframerate(); smp=struct.unpack('<%dh'%n,raw)
step=sr//FPS; env=[min(1,math.sqrt(sum(x*x for x in smp[k:k+step])/max(1,len(smp[k:k+step])))/6000) for k in range(0,n,step)]

# 3. map (generic): world110 base + 10m detail clipped to the zoomed regions + per-scene highlights
from shapely.geometry import shape, box, mapping
from shapely.ops import unary_union
import re
S=100.0; AR=1080/1920
def X(lon): return (lon+180)*S
def Y(lat): return (90-lat)*S
def key(s): return re.sub(r'[^a-z]','',(s or '').lower())
ALIAS={'usa':'unitedstatesofamerica','unitedstates':'unitedstatesofamerica','us':'unitedstatesofamerica','uk':'unitedkingdom','britain':'unitedkingdom','uae':'unitedarabemirates','czechia':'czechrepublic','turkiye':'turkey','burma':'myanmar','ivorycoast':'ivorycoast','eswatini':'eswatini','swaziland':'eswatini','macedonia':'northmacedonia','drc':'democraticrepublicofthecongo','congo':'republicofthecongo'}
def load(p): return json.load(open(H+'/'+p))['features']
W110=load('countries110.json'); W10=load('ne10.json')
def fkeys(f):
    p=f['properties']; return {key(p.get(k)) for k in ('ADMIN','NAME','NAME_LONG','SOVEREIGNT') if p.get(k)}
def find(feats,name):
    k=key(name); k=ALIAS.get(k,k)
    for f in feats:
        if k in fkeys(f): return f
    return None
def mainbbox(f):
    g=shape(f['geometry']); ps=list(g.geoms) if g.geom_type=='MultiPolygon' else [g]
    ps=[p for p in ps if p.bounds[0]>-170 or all(q.bounds[0]<-170 for q in ps)] or ps
    mx_=max(p.envelope.area for p in ps); keep=[p for p in ps if p.envelope.area>=0.05*mx_]
    b=unary_union(keep).bounds; return b
SH=[1.9,1.0,0.55,1.3,0.45,2.2,1.0,0.6]
cams=[];hls=[]
for i,s in enumerate(sc['scenes']):
    names=[n for n in (s.get('countries') or []) if isinstance(n,str)][:4]
    fs=[f for f in (find(W110,n) for n in names) if f]
    pts=[]
    for f in fs:
        b=mainbbox(f); pts+=[(b[0],b[1]),(b[2],b[3])]
    for a in s.get('arrows') or []:
        try: pts+=[(a[0],a[1]),(a[2],a[3])]
        except Exception: pass
    fo=s.get('focus'); fok=None
    try:
        if fo and len(fo)==3: fok=(float(fo[0]),float(fo[1]),max(4,min(200,float(fo[2]))))
    except Exception: fok=None
    if pts:
        x0=min(p[0] for p in pts);x1=max(p[0] for p in pts);y0=min(p[1] for p in pts);y1=max(p[1] for p in pts)
        cx,cy=(x0+x1)/2,(y0+y1)/2; span=max((x1-x0)*1.5,(y1-y0)*1.5*AR,6)
        mg=0.25*max(x1-x0,(y1-y0))
        if fok and x0-mg<=fok[0]<=x1+mg and y0-mg<=fok[1]<=y1+mg: cx,cy,span=fok   # a close-up the planner asked for, inside the shown area
        else: span*=SH[i%len(SH)]
    elif fok: cx,cy,span=fok
    else: cx,cy,span=10,20,140
    span=max(5,min(160,span))
    vis=span/AR; cy=max(-90+vis/2,min(90-vis/2,cy)) if vis<180 else 15
    if not fs:
        from shapely.geometry import Point
        pt=Point(cx,cy)
        for f in W110:
            try:
                if shape(f['geometry']).buffer(0).contains(pt): fs=[f]; names=[f['properties']['ADMIN']]; break
            except Exception: pass
    cams.append((cx,cy,span)); hls.append((names,fs))
narrow=[c for c in cams if c[2]<=45]
paths_d=''
if narrow:
    boxes=[box(c[0]-c[2]*0.8,c[1]-c[2]/AR*0.8,c[0]+c[2]*0.8,c[1]+c[2]/AR*0.8) for c in narrow]
    U=unary_union(boxes); eps=min(c[2] for c in narrow)/1080*0.6
    def gpath(geom,epsv):
        if geom.is_empty: return ''
        g=geom.simplify(epsv,preserve_topology=False)
        stack=[g]; o=[]
        while stack:
            q=stack.pop()
            if q.is_empty: continue
            if hasattr(q,'geoms'): stack+=list(q.geoms); continue
            if q.geom_type!='Polygon': continue
            for r in [q.exterior]+list(q.interiors):
                c=list(r.coords)
                if len(c)>2: o.append('M'+' L'.join('%.1f,%.1f'%(X(x),Y(y)) for x,y in c)+'Z')
        return ' '.join(o)
    allg=[]
    for f in W10:
        try:
            g=shape(f['geometry']).buffer(0)
            if g.intersects(U): allg.append(g.intersection(U))
        except Exception: pass
    paths_d=gpath(unary_union(allg),eps) if allg else ''
def gp110(f):
    g=f['geometry']; ps=g['coordinates'] if g['type']=='MultiPolygon' else [g['coordinates']]
    return ' '.join('M'+' L'.join('%.1f,%.1f'%(X(p[0]),Y(p[1])) for p in r)+'Z' for poly in ps for r in poly)
base_d=' '.join(gp110(f) for f in W110)
hl_groups=[]
for i,(names,fs) in enumerate(hls):
    cx,cy,span=cams[i]; d_=''
    if span<=45 and fs:
        bx=box(cx-span*0.9,cy-span/AR*0.9,cx+span*0.9,cy+span/AR*0.9)
        gl=[]
        for n in names:
            f=find(W10,n)
            if f:
                try:
                    g=shape(f['geometry']).buffer(0)
                    if g.intersects(bx): gl.append(g.intersection(bx))
                except Exception: pass
        d_=gpath(unary_union(gl),eps) if gl else ''
    if not d_: d_=' '.join(gp110(f) for f in fs)
    hl_groups.append('<path id="hl%d" class="hl" d="%s" style="opacity:0"/>'%(i,d_))
# arrows + suez line
LINES=json.load(open(H+'/lines_osm.json')) if os.path.exists(H+'/lines_osm.json') else {}
arrows_svg=''; arrow_ids={}
for i,s in enumerate(sc['scenes']):
    for k,a in enumerate((s.get('arrows') or [])[:3]):
        try: arrows_svg+='<path id="ar%d_%d" class="ar" pathLength="1" d="M%.1f,%.1f L%.1f,%.1f"/>'%(i,k,X(a[0]),Y(a[1]),X(a[2]),Y(a[3]))
        except Exception: pass
txt_all=(sc.get('title','')+' '+' '.join(s.get('vo','') for s in sc['scenes'])).lower()
osm_svg=''
if 'suez' in LINES and ('السويس' in txt_all or 'suez' in txt_all):
    osm_svg=''.join('<path class="cn" pathLength="1" d="M'+' L'.join('%.1f,%.1f'%(X(p[0]),Y(p[1])) for p in ln)+'"/>' for ln in LINES['suez'])
lpins=''.join('<circle id="lp%d_%d" cx="%.1f" cy="%.1f" r="0" class="pin"/>'%(i,k,X(float(lb['lon'])),Y(float(lb['lat']))) for i,s_ in enumerate(sc['scenes']) for k,lb in enumerate((s_.get('labels') or [])[:2]) if isinstance(lb,dict) and lb.get('text') and isinstance(lb.get('lon'),(int,float)) and isinstance(lb.get('lat'),(int,float)) and -180<=lb['lon']<=180 and -90<=lb['lat']<=90)
pins=''.join('<circle id="pin%d" cx="%.1f" cy="%.1f" r="0" class="pin"/>'%(i,X(c[0]),Y(c[1])) for i,c in enumerate(cams) if c[2]<12)
Wm=360*S; Hm=180*S
svg=(f'<svg id="map" width="1080" height="1920" viewBox="0 0 {Wm} {Hm}" preserveAspectRatio="xMidYMid slice"><rect x="-30000" y="-30000" width="{Wm+60000}" height="{Hm+60000}" fill="#17335c"/>'
     f'<path class="c" d="{base_d}"/><path class="c" d="{paths_d}"/>{"".join(hl_groups)}{osm_svg}{arrows_svg}{pins}{lpins}</svg>')


# 4. characters
def face(k,skin,hair,shirt,hat):
    return f'''<svg class="chr" id="ch_{k}" viewBox="0 0 200 260" width="230" height="300"><rect x="35" y="170" width="130" height="90" rx="40" fill="{shirt}" stroke="#222" stroke-width="4"/><circle cx="100" cy="100" r="68" fill="{skin}" stroke="#222" stroke-width="5"/>{hat}<circle cx="76" cy="92" r="11" fill="#fff" stroke="#222" stroke-width="3"/><circle cx="124" cy="92" r="11" fill="#fff" stroke="#222" stroke-width="3"/><circle id="pl_{k}" cx="76" cy="94" r="5" fill="#222"/><circle id="pr_{k}" cx="124" cy="94" r="5" fill="#222"/><path d="M58 74 Q76 62 94 72" stroke="#222" stroke-width="5" fill="none"/><path d="M106 72 Q124 62 142 74" stroke="#222" stroke-width="5" fill="none"/><path d="M100 100 L94 122 L106 122" stroke="#a5683a" stroke-width="4" fill="none"/><ellipse id="m_{k}" cx="100" cy="146" rx="22" ry="3" fill="#6b1a1a" stroke="#222" stroke-width="3"/></svg>'''
hatA='<path d="M34 78 Q100 -10 166 78 Q100 50 34 78Z" fill="#f09a2a" stroke="#222" stroke-width="5"/>'
hairB='<path d="M32 100 Q32 20 100 22 Q168 20 168 100 Q150 56 100 52 Q50 56 32 100Z" fill="#5b2a6e" stroke="#222" stroke-width="5"/><path d="M32 100 L30 170 L55 170 L50 100Z M168 100 L170 170 L145 170 L150 100Z" fill="#5b2a6e" stroke="#222" stroke-width="4"/>'
hatN='<path d="M40 60 Q100 8 160 60 L160 70 Q100 40 40 70Z" fill="#333" stroke="#222" stroke-width="5"/>'
chars={'n':face('n','#f0c8a0','#222','#b02a2a',hatN),'a':face('a','#f2c9a0','#222','#2d62a8',hatA),'b':face('b','#f6d3b0','#5b2a6e','#8e3a8e',hairB)}

# 5. html
NS=len(sc['scenes']);TOT=round(total,2)
POS={'n':'left:40px','a':'left:425px','b':'right:40px'}
html=f"""<!doctype html><html lang="ar"><head><meta charset="UTF-8"/><meta name="viewport" content="width=1080, height=1920"/>
<script src="https://cdn.jsdelivr.net/npm/gsap@3.14.2/dist/gsap.min.js"></script>
<style>@font-face{{font-family:"DejaVu Sans";src:local("DejaVu Sans")}}*{{margin:0;padding:0;box-sizing:border-box}}html,body{{width:1080px;height:1920px;overflow:hidden;background:#0a0a0a}}
#root{{position:relative;width:1080px;height:1920px;overflow:hidden;font-family:"DejaVu Sans",sans-serif;direction:rtl}}
.c{{fill:#e8d9b0;stroke:#b8a77c;stroke-width:.5;vector-effect:non-scaling-stroke}}.hl{{fill:#e0603f;stroke:#a83f26;stroke-width:.6;vector-effect:non-scaling-stroke}}
.cn{{fill:none;stroke:#3fa9ff;stroke-width:5;stroke-linecap:round;stroke-linejoin:round;vector-effect:non-scaling-stroke}}
.pin{{fill:#fff3;stroke:#fff;stroke-width:4;vector-effect:non-scaling-stroke}}.ar{{fill:none;stroke:#ffd24a;stroke-width:8;stroke-linecap:round;vector-effect:non-scaling-stroke;stroke-dasharray:0 1}}
#map{{position:absolute;left:0;top:0}}.chr{{position:absolute;bottom:560px;opacity:0}}#ch_n{{left:40px}}#ch_a{{left:425px}}#ch_b{{right:40px}}
.lab{{position:absolute;background:#0b1f3add;color:#fff;padding:14px 30px;border-radius:40px;font-size:54px;font-weight:700;opacity:0;white-space:nowrap;transform:translateX(-50%)}}
.cap{{position:absolute;left:60px;right:60px;bottom:170px;background:#0b1226f2;color:#fff;font-size:64px;line-height:1.5;padding:30px;border-radius:36px;text-align:center;font-weight:700;opacity:0}}
.cap span{{opacity:.55}}.cap span.on{{opacity:1;color:#ffd24a}}#src{{position:absolute;left:20px;bottom:40px;color:#fff;background:#000c;padding:6px 12px;border-radius:10px;font-size:26px;direction:ltr}}
</style></head><body>
<div id="root" data-composition-id="main" data-start="0" data-duration="{TOT}" data-width="1080" data-height="1920">
{svg}{chars['n']}{chars['a']}{chars['b']}
<audio id="vo" src="assets/voice.wav" data-start="0" data-duration="{TOT}" data-track-index="9"></audio>
<div id="src" class="clip" data-start="0" data-duration="{TOT}" data-track-index="8">Map: Natural Earth, OpenStreetMap contributors (ODbL)</div>
"""
def scr(i,lon,lat):
    cx,cy,span=cams[i]; w=span*S; h=w/AR
    px=(X(lon)-(X(cx)-w/2))/w*1080; py=(Y(lat)-(Y(cy)-h/2))/h*1920
    return px,py
def snap(i,lb):
    try:
        lon,lat=float(lb['lon']),float(lb['lat'])
    except Exception: lon=lat=None
    names,fs=hls[i]
    if fs:
        bs=[mainbbox(f) for f in fs]; b=(min(q[0] for q in bs),min(q[1] for q in bs),max(q[2] for q in bs),max(q[3] for q in bs)); m=0.5*max(b[2]-b[0],b[3]-b[1])
        if lon is None or not(b[0]-m<=lon<=b[2]+m and b[1]-m<=lat<=b[3]+m): lon,lat=(b[0]+b[2])/2,(b[1]+b[3])/2
    if lon is None: lon,lat=cams[i][0],cams[i][1]
    return scr(i,lon,lat)
labpos={}
for i,s in enumerate(sc['scenes']):
    ws=s['vo'].split(); html+=f'<div id="cap{i}" class="cap clip" data-start="0" data-duration="{TOT}" data-track-index="{20+i}">'+' '.join(f'<span id="w{i}_{j}">{w}</span>' for j,w in enumerate(ws))+'</div>\n'
    placed=[]
    for k,lb in enumerate((s.get('labels') or [])[:2]):
        if not isinstance(lb,dict) or not lb.get('text'): continue
        px,py=snap(i,lb); px=min(900,max(180,px)); py=min(1000,max(260,py))
        for (qx,qy) in placed:
            if abs(py-qy)<110 and abs(px-qx)<420: py=qy+120 if qy+120<1000 else qy-120
        placed.append((px,py)); labpos[(i,k)]=1
        html+=f'<div id="l{i}_{k}" class="lab clip" data-start="0" data-duration="{TOT}" data-track-index="{40+i*2+k}" style="left:{px:.0f}px;top:{py:.0f}px">{lb["text"]}</div>\n'
html+='</div><script>\nconst tl=gsap.timeline({paused:true});const ENV='+json.dumps([round(e,2) for e in env])+';const FPS='+str(FPS)+';\n'
html+=f'const vb={{x:0,y:0,w:{Wm},h:{Hm}}};const set=()=>document.getElementById("map").setAttribute("viewBox",vb.x+" "+vb.y+" "+vb.w+" "+vb.h);\n'
cx0,cy0,sp0=cams[0]; w0=sp0*S; h0=w0/AR
html+=f'Object.assign(vb,{{x:{X(cx0)-w0/2:.1f},y:{Y(cy0)-h0/2:.1f},w:{w0:.1f},h:{h0:.1f}}});set();\n'
html+='tl.set("#ch_n,#ch_a,#ch_b",{opacity:1},0);\n'
for i,s in enumerate(sc['scenes']):
    t0=starts[i];d=auds[i][1]; cx,cy,span=cams[i]; w=span*S; h=w/AR
    html+=f'tl.to(vb,{{x:{X(cx)-w/2:.1f},y:{Y(cy)-h/2:.1f},w:{w:.1f},h:{h:.1f},duration:1.2,ease:"power2.inOut",onUpdate:set}},{max(0,t0-0.2):.2f});\n'
    html+=f'tl.to("#hl{i}",{{opacity:{0.4 if cams[i][2]<12 else 1},duration:.4}},{t0:.2f}).to("#hl{i}",{{opacity:0,duration:.25}},{t0+d+GAP-.1:.2f});\n'
    if cams[i][2]<12: html+=f'tl.to("#pin{i}",{{attr:{{r:{cams[i][2]*S*0.03:.1f}}},duration:.4}},{t0+.3:.2f}).to("#pin{i}",{{attr:{{r:0}},duration:.2}},{t0+d+GAP-.1:.2f});\n'
    html+=f'tl.to("#cap{i}",{{opacity:1,duration:.15}},{t0:.2f}).to("#cap{i}",{{opacity:0,duration:.1}},{t0+d+GAP-0.2:.2f});\n'
    nw=len(s['vo'].split())
    for j in range(nw): html+=f'tl.set("#w{i}_{j}",{{className:"on"}},{t0+d*j/nw:.2f});tl.set("#w{i}_{j}",{{className:""}},{t0+d*(j+1)/nw:.2f});\n'
    for k in range(2):
        if (i,k) in labpos and ('id="lp%d_%d"'%(i,k)) in svg: html+=f'tl.to("#lp{i}_{k}",{{attr:{{r:{max(cams[i][2]*S*0.012,40):.1f}}},duration:.4}},{t0+.3+k*.8:.2f}).to("#lp{i}_{k}",{{attr:{{r:0}},duration:.2}},{t0+d+GAP-.1:.2f});\n'
        if (i,k) in labpos: html+=f'tl.to("#l{i}_{k}",{{opacity:1,duration:.3}},{t0+.3+k*.8:.2f}).to("#l{i}_{k}",{{opacity:0,duration:.2}},{t0+d+GAP-.1:.2f});\n'
    for k in range(3):
        if s.get('arrows') and k<len(s['arrows']) and k<3: html+=f'tl.to("#ar{i}_{k}",{{strokeDasharray:"1 0",duration:{min(2.2,d):.2f},ease:"none"}},{t0+.2+k*.4:.2f}).to("#ar{i}_{k}",{{opacity:0,duration:.2}},{t0+d+GAP-.1:.2f});\n'
    if osm_svg and ('السويس' in s['vo'] or 'suez' in s['vo'].lower() or 'قناة' in s['vo']):
        html+=f'tl.fromTo(".cn",{{strokeDasharray:"0 1"}},{{strokeDasharray:"1 0",duration:{min(2.0,d):.2f},ease:"none"}},{t0:.2f});\n'
    sp_=s["spk"] if s["spk"] in ("n","a","b") else ("a" if s["spk"]=="c" else "n"); sp_= "b" if s["spk"]=="c" else sp_
    html+=f'tl.to({{p:0}},{{p:1,duration:{d:.2f},ease:"none",onUpdate:function(){{const e=ENV[Math.min(ENV.length-1,Math.floor(({t0:.2f}+this.progress()*{d:.2f})*FPS))]||0;const m=document.getElementById("m_{sp_}");m.setAttribute("ry",3+e*26);m.setAttribute("rx",22-e*6);document.getElementById("ch_{sp_}").style.transform="translateY("+(-e*14)+"px) scale("+(1+e*.05)+")";}}}},{t0:.2f});\n'
    for o in ('n','a','b'):
        if o!=sp_: html+=f'tl.set("#m_{o}",{{attr:{{ry:3,rx:22}}}},{t0:.2f});tl.set("#ch_{o}",{{y:0}},{t0:.2f});\n'
html+='window.__timelines["main"]=tl;tl.seek(0);\n</script></body></html>'
open(OUT+'/index.html','w').write(html); print('built',TOT,'s',len(html)//1024,'KB')
