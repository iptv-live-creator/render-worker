import json,subprocess,sys,os,math,struct,wave,asyncio
H=os.path.dirname(os.path.abspath(__file__)); OUT=sys.argv[2] if len(sys.argv)>2 else '/tmp/hf/suez'
sc=json.load(open(sys.argv[1])); os.makedirs(OUT+'/assets',exist_ok=True)
VOICES={'a':('ar-EG-ShakirNeural','+0Hz'),'b':('ar-EG-SalmaNeural','+0Hz'),'c':('ar-EG-ShakirNeural','+40Hz')}
FPS=15; GAP=0.35
# 1. voices
auds=[]
for i,s in enumerate(sc['scenes']):
    v,p=VOICES[s['spk']]; f=f'{OUT}/assets/s{i}.mp3'
    for _t in range(4):
        r=subprocess.run(['python3','-m','edge_tts','--voice',v,'--pitch',p,'--text',s['vo'],'--write-media',f],capture_output=True,timeout=60)
        if r.returncode==0 and os.path.getsize(f)>1000: break
    else: raise SystemExit('tts failed: '+r.stderr.decode()[-200:])
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
# 3. map
d=json.load(open(H+'/ne10.json'))
X0,X1,Y0,Y1,S=18,48,18,44,100
P=lambda lon,lat:(round((lon-X0)*S,1),round((Y1-lat)*S,1))
def ring(r):
    o=[];l=None
    for pt in r:
        if not(X0-1<=pt[0]<=X1+1 and Y0-1<=pt[1]<=Y1+1): continue
        q=P(pt[0],pt[1])
        if l and abs(q[0]-l[0])<.8 and abs(q[1]-l[1])<.8: continue
        o.append(q);l=q
    return o
HI=set(sc.get('highlight',['Egypt']))
paths=[]
for f in d['features']:
    g=f['geometry'];ps=g['coordinates'] if g['type']=='MultiPolygon' else [g['coordinates']]
    dd=''.join('M'+' L'.join('%s,%s'%q for q in rr)+'Z ' for p in ps for r in p for rr in [ring(r)] if len(rr)>2)
    if dd: paths.append('<path class="%s" d="%s"/>'%('eg' if f['properties']['ADMIN'] in HI else 'c',dd))
cn=json.load(open(H+'/canal_suez.json'))
cp=''.join('<path class="cn" d="M'+' L'.join('%s,%s'%P(g['lon'],g['lat']) for g in e['geometry'])+'"/>' for e in cn['elements'])
allp=[P(g['lon'],g['lat']) for e in cn['elements'] for g in e['geometry']]
cx=sum(p[0] for p in allp)/len(allp);cy=sum(p[1] for p in allp)/len(allp)
pa=min(allp,key=lambda p:p[1]);pb=max(allp,key=lambda p:p[1])
W=(X1-X0)*S;Hh=(Y1-Y0)*S
svg=f'<svg id="map" width="1080" height="1920" viewBox="0 0 {W} {Hh}" preserveAspectRatio="xMidYMid slice"><rect x="-500" y="-500" width="{W+1000}" height="{Hh+1000}" fill="#17335c"/>{"".join(paths)}{cp}<circle id="pa" cx="{pa[0]}" cy="{pa[1]}" r="0" class="pin"/><circle id="pb" cx="{pb[0]}" cy="{pb[1]}" r="0" class="pin"/></svg>'
# 4. characters (inline svg, mouth id m_<k>)
def face(k,skin,hair,shirt,hat):
    return f'''<svg class="chr" id="ch_{k}" viewBox="0 0 200 260" width="230" height="300"><rect x="35" y="170" width="130" height="90" rx="40" fill="{shirt}" stroke="#222" stroke-width="4"/><circle cx="100" cy="100" r="68" fill="{skin}" stroke="#222" stroke-width="5"/>{hat}<circle cx="76" cy="92" r="11" fill="#fff" stroke="#222" stroke-width="3"/><circle cx="124" cy="92" r="11" fill="#fff" stroke="#222" stroke-width="3"/><circle id="pl_{k}" cx="76" cy="94" r="5" fill="#222"/><circle id="pr_{k}" cx="124" cy="94" r="5" fill="#222"/><path d="M58 74 Q76 62 94 72" stroke="#222" stroke-width="5" fill="none"/><path d="M106 72 Q124 62 142 74" stroke="#222" stroke-width="5" fill="none"/><path d="M100 100 L94 122 L106 122" stroke="#a5683a" stroke-width="4" fill="none"/><ellipse id="m_{k}" cx="100" cy="146" rx="22" ry="3" fill="#6b1a1a" stroke="#222" stroke-width="3"/></svg>'''
hatA='<path d="M34 78 Q100 -10 166 78 Q100 50 34 78Z" fill="#f09a2a" stroke="#222" stroke-width="5"/>'
hairB='<path d="M32 100 Q32 20 100 22 Q168 20 168 100 Q150 56 100 52 Q50 56 32 100Z" fill="#5b2a6e" stroke="#222" stroke-width="5"/><path d="M32 100 L30 170 L55 170 L50 100Z M168 100 L170 170 L145 170 L150 100Z" fill="#5b2a6e" stroke="#222" stroke-width="4"/>'
chars={'a':face('a','#f2c9a0','#222','#2d62a8',hatA),'b':face('b','#f6d3b0','#5b2a6e','#8e3a8e',hairB)}
# 5. html
caps=[];tl=[]
NS=len(sc['scenes']);TOT=round(total,2)
html=f'''<!doctype html><html lang="ar"><head><meta charset="UTF-8"/><meta name="viewport" content="width=1080, height=1920"/>
<script src="https://cdn.jsdelivr.net/npm/gsap@3.14.2/dist/gsap.min.js"></script>
<style>@font-face{{font-family:"DejaVu Sans";src:local("DejaVu Sans")}}*{{margin:0;padding:0;box-sizing:border-box}}html,body{{width:1080px;height:1920px;overflow:hidden;background:#0a0a0a}}
#root{{position:relative;width:1080px;height:1920px;overflow:hidden;font-family:"DejaVu Sans",sans-serif;direction:rtl}}
.c{{fill:#e8d9b0;stroke:#b8a77c;stroke-width:.5;vector-effect:non-scaling-stroke}}.eg{{fill:#e0603f;stroke:#a83f26;stroke-width:.6;vector-effect:non-scaling-stroke}}
.cn{{fill:none;stroke:#3fa9ff;stroke-width:5;stroke-linecap:round;stroke-linejoin:round}}.pin{{fill:#fff;stroke:#e05a3c;stroke-width:1.5;vector-effect:non-scaling-stroke}}
#map{{position:absolute;left:0;top:0}}.chr{{position:absolute;bottom:560px;opacity:0}}#ch_a{{left:60px}}#ch_b{{right:60px}}
.lab{{position:absolute;background:#0b1f3add;color:#fff;padding:14px 30px;border-radius:40px;font-size:54px;font-weight:700;opacity:0;white-space:nowrap}}
.cap{{position:absolute;left:60px;right:60px;bottom:170px;background:#000a;color:#fff;font-size:64px;line-height:1.5;padding:30px;border-radius:36px;text-align:center;font-weight:700;opacity:0}}
.cap span{{opacity:.55}}.cap span.on{{opacity:1;color:#ffd24a}}#src{{position:absolute;left:20px;bottom:40px;color:#fff;background:#000c;padding:6px 12px;border-radius:10px;font-size:26px;direction:ltr}}
</style></head><body>
<div id="root" data-composition-id="main" data-start="0" data-duration="{TOT}" data-width="1080" data-height="1920">
{svg}{chars['a']}{chars['b']}
<audio id="vo" src="assets/voice.wav" data-start="0" data-duration="{TOT}" data-track-index="9"></audio>
<div id="src" class="clip" data-start="0" data-duration="{TOT}" data-track-index="8">Map: Natural Earth, OpenStreetMap contributors (ODbL)</div>
'''
for i,s in enumerate(sc['scenes']):
    ws=s['vo'].split(); html+=f'<div id="cap{i}" class="cap clip" data-start="0" data-duration="{TOT}" data-track-index="{20+i}">'+' '.join(f'<span id="w{i}_{j}">{w}</span>' for j,w in enumerate(ws))+'</div>\n'
    for k,lb in enumerate(s.get('label',[])):
        if lb: html+=f'<div id="l{i}_{k}" class="lab clip" data-start="0" data-duration="{TOT}" data-track-index="{40+i*2+k}" style="left:{520 if k==0 else 560}px;top:{560 if k==0 else 1240}px">{lb}</div>\n'
html+='</div><script>\nconst tl=gsap.timeline({paused:true});const ENV='+json.dumps([round(e,2) for e in env])+';const FPS='+str(FPS)+';\n'
html+=f'const vb={{x:0,y:0,w:{W},h:{Hh}}};const set=()=>document.getElementById("map").setAttribute("viewBox",vb.x+" "+vb.y+" "+vb.w+" "+vb.h);const ar=1080/1920;const box=(cx,cy,w)=>({{x:cx-w/2,y:cy-w/ar/2,w:w,h:w/ar}});\n'
html+=f'const REG=box({cx-80},{cy-60},1500),CAN=box({cx},{cy},340),CAN2=box({cx},{cy+20},420);Object.assign(vb,REG);set();\n'
html+='tl.set(".cn",{strokeDasharray:"0 1000"},0);\n'
html+=f'tl.set("#ch_a,#ch_b",{{opacity:1}},0);\n'
for i,s in enumerate(sc['scenes']):
    t0=starts[i];d=auds[i][1];tgt={'region':'REG','canal':'CAN' if i%2 else 'CAN2'}[s['focus']]
    html+=f'tl.to(vb,{{x:{tgt}.x,y:{tgt}.y,w:{tgt}.w,h:{tgt}.h,duration:1.2,ease:"power2.inOut",onUpdate:set}},{max(0,t0-0.2):.2f});\n'
    html+=f'tl.to("#cap{i}",{{opacity:1,duration:.15}},{t0:.2f}).to("#cap{i}",{{opacity:0,duration:.1}},{t0+d+GAP-0.2:.2f});\n'
    nw=len(s['vo'].split())
    for j in range(nw): html+=f'tl.set("#w{i}_{j}",{{className:"on"}},{t0+d*j/nw:.2f});tl.set("#w{i}_{j}",{{className:""}},{t0+d*(j+1)/nw:.2f});\n'
    for k,lb in enumerate(s.get('label',[])):
        if lb: html+=f'tl.to("#l{i}_{k}",{{opacity:1,duration:.3}},{t0+.3+k*.8:.2f}).to("#l{i}_{k}",{{opacity:0,duration:.2}},{t0+d+GAP-.1:.2f});\n'
    if s.get('draw'):
        html+=f'tl.to("#pa,#pb",{{attr:{{r:5}},duration:.3}},{t0:.2f});tl.fromTo(".cn",{{strokeDasharray:"0 1000"}},{{strokeDasharray:"1000 0",duration:{min(2.0,d):.2f},ease:"none"}},{t0:.2f});\n'
    # talking: mouth envelope + bob for the speaker, small idle for the other
    html+=f'tl.to({{p:0}},{{p:1,duration:{d:.2f},ease:"none",onUpdate:function(){{const e=ENV[Math.min(ENV.length-1,Math.floor(({t0:.2f}+this.progress()*{d:.2f})*FPS))]||0;const m=document.getElementById("m_{s["spk"]}");m.setAttribute("ry",3+e*26);m.setAttribute("rx",22-e*6);document.getElementById("ch_{s["spk"]}").style.transform="translateY("+(-e*14)+"px) scale("+(1+e*.05)+")";}}}},{t0:.2f});\n'
    other='b' if s['spk']=='a' else 'a'
    html+=f'tl.set("#m_{other}",{{attr:{{ry:3,rx:22}}}},{t0:.2f});tl.set("#ch_{other}",{{y:0}},{t0:.2f});\n'
html+='window.__timelines["main"]=tl;tl.seek(0);\n</script></body></html>'
open(OUT+'/index.html','w').write(html); print('built',TOT,'s',len(html)//1024,'KB')
