import io,re
files=open(r"C:\Users\User\Downloads\sd\_qa\sampleC.txt",encoding="utf-8").read().strip()
tmpl=open(r"C:\Users\User\Downloads\sd\_qa\wf_deepread.js",encoding="utf-8").read()
new=re.sub(r'const FILES = \[.*?\]', 'const FILES = ['+files+']', tmpl, count=1, flags=re.S)
new=new.replace("nullware-deep-read-100","nullware-deep-read-100c")
io.open(r"C:\Users\User\Downloads\sd\_qa\wf_deepread_c.js","w",encoding="utf-8").write(new)
print("wrote wf_deepread_c.js; FILES count:", files.count(",")+1)
