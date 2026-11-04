import json, pathlib, urllib.request, concurrent.futures, zipfile, xml.etree.ElementTree as E
from PIL import Image, ImageOps, ImageDraw
p=pathlib.Path(__file__).parent
pages=json.loads((p/'canva-pages.json').read_text())
def fetch(q):
    f=p/f"slide-{q['index']:02}.png"
    urllib.request.urlretrieve(q['thumbnail']['url'], f)
    return f
files=list(concurrent.futures.ThreadPoolExecutor(8).map(fetch,pages))
sheet=Image.new('RGB',(1200,7*365),'#eeeeee'); d=ImageDraw.Draw(sheet)
for i,f in enumerate(files):
    im=Image.open(f).convert('RGB');im.thumbnail((596,335));x=(i%2)*600;y=(i//2)*365
    if i<14:sheet.paste(im,(x,y+25));d.text((x+10,y+5),str(i+1),fill='black')
sheet.save(p/'reference-1.jpg')
sheet=Image.new('RGB',(1800,7*365),'#eeeeee'); d=ImageDraw.Draw(sheet)
for i,f in enumerate(files[14:]):
    im=Image.open(f).convert('RGB');im.thumbnail((596,335));x=(i%3)*600;y=(i//3)*365
    sheet.paste(im,(x,y+25));d.text((x+10,y+5),str(i+15),fill='black')
sheet.save(p/'reference-2.jpg')
z=zipfile.ZipFile(r'C:\Users\typical\Desktop\Báo cáo BTL MMHCS - đã định dạng.docx')
n={'w':'http://schemas.openxmlformats.org/wordprocessingml/2006/main','a':'http://schemas.openxmlformats.org/drawingml/2006/main','r':'http://schemas.openxmlformats.org/officeDocument/2006/relationships'}
rels={e.attrib['Id']:e.attrib['Target'] for e in E.fromstring(z.read('word/_rels/document.xml.rels'))}
root=E.fromstring(z.read('word/document.xml')); out=[]
for q in root.findall('.//w:p',n):
    txt=''.join(e.text or '' for e in q.findall('.//w:t',n))
    ids=[rels[e.attrib['{'+n['r']+'}embed']] for e in q.findall('.//a:blip',n) if '{'+n['r']+'}embed' in e.attrib]
    if txt or ids: out.append({'text':txt,'images':ids})
(p/'report-map.json').write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf8')
imgs=list(p.glob('image*')); thumbs=[]
for f in imgs:
    try:
        im=Image.open(f).convert('RGB');im.thumbnail((380,240));thumbs.append((f.name,im.copy()))
    except:pass
sheet=Image.new('RGB',(1200,((len(thumbs)+2)//3)*280),'#ddd');d=ImageDraw.Draw(sheet)
for i,(name,im) in enumerate(thumbs):
    x=(i%3)*400;y=(i//3)*280;sheet.paste(im,(x,y+30));d.text((x+5,y+5),name,fill='black')
sheet.save(p/'report-images.jpg')
print('done',len(thumbs),'images')
