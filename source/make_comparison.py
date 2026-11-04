from PIL import Image, ImageDraw, ImageFont
from pathlib import Path
out=Path(__file__).parent
im=Image.new('RGB',(1700,1250),'white');d=ImageDraw.Draw(im)
font=ImageFont.truetype('C:/Windows/Fonts/segoeui.ttf',42)
bold=ImageFont.truetype('C:/Windows/Fonts/segoeuib.ttf',43)
cols=[0,520,1080,1700];rows=[0,170,440,710,980,1250]
data=[['Tiêu chí','TLS 1.2','TLS 1.3'],['Bắt tay đầy đủ','Thông thường 2-RTT','Thông thường 1-RTT, có thể thêm lượt nếu retry'],['Forward Secrecy','Có khi dùng (EC)DHE','Có với (EC)DHE; PSK thuần không có'],['Bảo vệ Handshake','Phần lớn bản tin đầu ở dạng rõ','Mã hóa sau ServerHello'],['ChangeCipherSpec','Dùng để chuyển trạng thái mật mã','Chỉ còn vì tương thích']]
for r,row in enumerate(data):
    for c,txt in enumerate(row):
        box=(cols[c],rows[r],cols[c+1],rows[r+1]);d.rectangle(box,fill='#eaf0fa' if r==0 else 'white',outline='#879abb',width=3)
        f=bold if r==0 else font;words=txt.split();lines=[];line=''
        for w in words:
            t=(line+' '+w).strip()
            if d.textlength(t,font=f)>cols[c+1]-cols[c]-55 and line:lines.append(line);line=w
            else:line=t
        if line:lines.append(line)
        y=rows[r]+(rows[r+1]-rows[r]-len(lines)*59)/2
        for line in lines:d.text((cols[c]+27,y),line,font=f,fill='#315ab5');y+=59
im.save(out/'tls-comparison.png')
