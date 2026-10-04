#!/usr/bin/env python3
# Copyright 2026 Stephane Bury
# SPDX-License-Identifier: Apache-2.0
#
# Generates InnoLayouts.java from the record declarations of the Inno Setup
# sources (Struct.pas / Shared.Struct.pas): number of strings and size of the
# binary part of each record of the setup data, and the offsets of the fields
# read by the plugin, for every format version (SetupID).
#
# Usage:
#   git clone https://github.com/jrsoftware/issrc.git
#   python3 gen_layouts.py issrc > ../src/io/github/realburst/arcana/plugin/innosetup/InnoLayouts.java
#
# To support a new Inno Setup release whose SetupID changed, add its tag to TAGS
# (one tag per SetupID: the last release using it) and run the script again.
import re, subprocess, sys
REPO = None
def show(tag, path):
    return subprocess.run(['git','-C',REPO,'show',f'{tag}:{path}'],capture_output=True,text=True,errors='replace').stdout
def structfile(tag):
    names=subprocess.run(['git','-C',REPO,'ls-tree','-r','--name-only',tag,'Projects'],capture_output=True,text=True).stdout.split()
    for n in names:
        if re.search(r'(^|/)(Shared\.)?Struct\.pas$',n) and 'Debug' not in n and 'CompilerInt' not in n: return n
def preprocess(src, unicode):
    src=re.sub(r'\{\$(IFDEF|IFNDEF)\s+UNICODE\}(.*?)(?:\{\$ELSE\}(.*?))?\{\$ENDIF\}',
               lambda m: (m.group(2) if (m.group(1)=='IFDEF')==unicode else (m.group(3) or '')), src, flags=re.S)
    src=re.sub(r'\{\$[^}]*\}','',src)
    src=re.sub(r'\(\*.*?\*\)','',src,flags=re.S)
    src=re.sub(r'\{[^}]*\}','',src,flags=re.S)
    src=re.sub(r'//[^\n]*','',src)
    return src
BUILTIN={'integer':4,'longint':4,'cardinal':4,'longword':4,'dword':4,'int32':4,'uint32':4,'tcolor':4,
 'word':2,'smallint':2,'byte':1,'boolean':1,'ansichar':1,'shortint':1,'char':None,
 'int64':8,'integer64':8,'uint64':8,'tfiletime':8,'tsha256digest':32,'tsha1digest':20,'tmd5digest':16,'tguid':16}
class Ctx: pass
def parse(src, unicode):
    c=Ctx(); c.enums={}; c.types={}; c.records={}
    BUILTIN['char']=2 if unicode else 1
    # enums
    for m in re.finditer(r'\b(T\w+)\s*=\s*\(([^)]*)\)\s*;',src):
        c.enums[m.group(1).lower()]=enum_max(m.group(2))
    for m in re.finditer(r'\b(T\w+)\s*=\s*(packed\s+)?set\s+of\s+(\w+)\s*;',src):
        c.types[m.group(1).lower()]=('set',m.group(3).lower())
    for m in re.finditer(r'\b(T\w+)\s*=\s*array\s*\[\s*(\d+)\s*\.\.\s*(\d+)\s*\]\s*of\s+(\w+)\s*;',src):
        c.types[m.group(1).lower()]=('arr',int(m.group(3))-int(m.group(2))+1,m.group(4).lower())
    for m in re.finditer(r'\b(T\w+)\s*=\s*(packed\s+)?record\b(.*?)\bend\s*;',src,flags=re.S):
        c.records[m.group(1).lower()]=(bool(m.group(2)),m.group(3))
    c.unicode=unicode
    return c
def enum_max(body):
    mx=-1; cur=-1
    for it in body.split(','):
        it=it.strip()
        if '=' in it: cur=int(it.split('=')[1].strip())
        else: cur+=1
        mx=max(mx,cur)
    return mx
def setsize(mx):
    n=mx//8+1
    return 4 if n==3 else n
def tsize(c, t):
    t=t.strip(); tl=t.lower()
    m=re.match(r'(packed\s+)?set\s+of\s+\((.*)\)$',t,flags=re.S|re.I)
    if m: return setsize(enum_max(m.group(2)))
    m=re.match(r'(packed\s+)?set\s+of\s+(\w+)$',t,flags=re.I)
    if m:
        e=m.group(2).lower()
        if e=='ansichar': return 32
        return setsize(c.enums[e])
    if t.startswith('('): return 1
    m=re.match(r'array\s*\[\s*(\d+)\s*\.\.\s*(\d+)\s*\]\s*of\s+(\w+)$',t,flags=re.I)
    if m: return (int(m.group(2))-int(m.group(1))+1)*tsize(c,m.group(3))
    if tl in ('string','ansistring'): return 'STR'
    if tl in BUILTIN: return BUILTIN[tl]
    if tl in c.enums: return 1
    if tl in c.types:
        k=c.types[tl]
        if k[0]=='set': return 32 if k[1]=='ansichar' else setsize(c.enums[k[1]])
        return k[1]*tsize(c,k[2])
    if tl in c.records: return recsize(c,tl)
    raise Exception('unknown type '+t)
def fields(c, body):
    out=[]
    for decl in split_decls(body):
        if ':' not in decl: continue
        names,typ=decl.split(':',1)
        for n in names.split(','):
            out.append((n.strip(),typ.strip()))
    return out
def split_decls(body):
    res=[];depth=0;cur=''
    for ch in body:
        if ch=='(' : depth+=1
        if ch==')' : depth-=1
        if ch==';' and depth==0: res.append(cur.strip()); cur=''
        else: cur+=ch
    if cur.strip(): res.append(cur.strip())
    return res
def recsize(c, name):
    packed,body=c.records[name]
    total=0; maxal=1
    for n,t in fields(c,body):
        s=tsize(c,t)
        if s=='STR': s=4
        if not packed:
            al=min(s,8) if s in (1,2,4,8) else 4
            if t.lower().startswith('array'): al=tsize(c,re.search(r'of\s+(\w+)',t,flags=re.I).group(1))
            total=(total+al-1)//al*al; maxal=max(maxal,al)
        total+=s
    if not packed: total=(total+maxal-1)//maxal*maxal
    return total
def layout(c, name):
    packed,body=c.records[name]
    nstr=nansi=0; off=0; f={}; strs=[]; ansis=[]
    for n,t in fields(c,body):
        tl=t.lower()
        if tl=='string' and c.unicode: strs.append(n); continue
        if tl=='string' or tl=='ansistring':
            (ansis if tl=='ansistring' else strs).append(n); continue
        m=re.match(r'(T\w+)$',t)
        if m and m.group(1).lower() in c.records and 'ansistring' in c.records[m.group(1).lower()][1].lower():
            # nested record whose first field is an AnsiString (TSetupFileVerification)
            sub=layout(c,m.group(1).lower()); ansis+=[n+'.'+a for a in sub['ansi']]
            for k,v in sub['fields'].items(): f[n+'.'+k]=(off+v[0],v[1],v[2])
            off+=sub['bin']; continue
        s=tsize(c,t)
        bits=None
        mm=re.match(r'(packed\s+)?set\s+of\s+\((.*)\)$',t,flags=re.S|re.I)
        if mm: bits=[x.split('=')[0].strip() for x in mm.group(2).split(',')]
        mm=re.match(r'(packed\s+)?set\s+of\s+(\w+)$',t,flags=re.I)
        if mm and mm.group(2).lower() in c.enums: bits=c.enumnames.get(mm.group(2).lower())
        mm=re.match(r'(T\w+)$',t)
        if mm and mm.group(1).lower() in c.types and c.types[mm.group(1).lower()][0]=='set':
            bits=c.enumnames.get(c.types[mm.group(1).lower()][1])
        f[n]=(off,s,bits); off+=s
    return {'str':strs,'ansi':ansis,'bin':off,'fields':f}
def enumnames(src):
    d={}
    for m in re.finditer(r'\b(T\w+)\s*=\s*\(([^)]*)\)\s*;',src):
        d[m.group(1).lower()]=[x.split('=')[0].strip() for x in m.group(2).split(',')]
    return d
RECS=['TSetupHeader','TSetupLanguageEntry','TSetupCustomMessageEntry','TSetupPermissionEntry','TSetupTypeEntry','TSetupComponentEntry','TSetupTaskEntry','TSetupDirEntry','TSetupISSigKeyEntry','TSetupFileEntry','TSetupFileLocationEntry','TSetupEncryptionHeader','TSetupLdrOffsetTable','TDiskSliceHeader']
def gen(tag, unicode):
    raw=show(tag,structfile(tag))
    src=preprocess(raw,unicode)
    c=parse(src,unicode); c.enumnames=enumnames(src)
    sid=re.search(r"SetupID:\s*TSetupID\s*=\s*'([^']*)'",src).group(1)
    if not unicode or "(u)" in raw.split('SetupID')[1][:200]:
        pass
    m=re.search(r"SetupID:\s*TSetupID\s*=\s*'([^']*)'\s*\+\s*' \(u\)'",preprocess(raw,True))
    if unicode and m: sid+=' (u)'
    out={'tag':tag,'id':sid,'unicode':unicode,'recs':{}}
    for r in RECS:
        if r.lower() in c.records:
            out['recs'][r]=layout(c,r.lower())
    return out
TAGS=['is-5_4_3','is-5_5_5','is-5_5_6','is-5_6_1','is-6_0_5','is-6_2_2','is-6_3_3','is-6_4_1','is-6_4_2','is-6_4_3','is-6_5_1','is-6_5_4','is-6_6_0','is-6_6_1','is-6_7_1','is-7_0_0_1','is-7_1_0']
def compfile(tag):
    names=subprocess.run(['git','-C',REPO,'ls-tree','-r','--name-only',tag,'Projects'],capture_output=True,text=True).stdout.split()
    for n in names:
        if re.search(r'/(Compress|Compression\.Base)\.pas$',n): return n
ENTRIES=[('TSetupLanguageEntry','NumLanguageEntries'),('TSetupCustomMessageEntry','NumCustomMessageEntries'),('TSetupPermissionEntry','NumPermissionEntries'),('TSetupTypeEntry','NumTypeEntries'),('TSetupComponentEntry','NumComponentEntries'),('TSetupTaskEntry','NumTaskEntries'),('TSetupDirEntry','NumDirEntries'),('TSetupISSigKeyEntry','NumISSigKeyEntries'),('TSetupFileEntry','NumFileEntries')]
def bit(fields, name, bitname):
    b=fields[name][2] or []
    return b.index(bitname) if bitname in b else -1
def emit_one(tag,u):
    o=gen(tag,u); R=o['recs']; H=R['TSetupHeader']; Hf=H['fields']
    src=preprocess(show(tag,structfile(tag)),u); c=parse(src,u); en=enumnames(src)
    kv=[]
    def put(k,v): kv.append(f'{k}={v}')
    put('u',1 if u else 0)
    put('stored',8 if re.search(r'StoredSize:\s*Int64',show(tag,compfile(tag))) else 4)
    put('H',f"{len(H['str'])}.{len(H['ansi'])}.{H['bin']}")
    put('H.AppName',H['str'].index('AppName')); put('H.AppVersion',H['str'].index('AppVersion'))
    for rec,num in ENTRIES:
        if rec in R:
            l=R[rec]; put(rec[6:-5],f"{len(l['str'])}.{len(l['ansi'])}.{l['bin']}"); put('H.'+num,Hf[num][0])
    put('H.NumFileLocationEntries',Hf['NumFileLocationEntries'][0])
    L=R['TSetupFileLocationEntry']; put('Location',L['bin'])
    for k in ['CompressMethod','SlicesPerDisk','Options','PasswordHash','PasswordSalt','PasswordTest','EncryptionKDFSalt','EncryptionKDFIterations','EncryptionBaseNonce']:
        if k in Hf: put('H.'+k,Hf[k][0])
    put('H.bit.Password',bit(Hf,'Options','shPassword')); put('H.bit.EncryptionUsed',bit(Hf,'Options','shEncryptionUsed'))
    cmn=en['tsetupcompressmethod']; put('cm','.'.join(x[2:] for x in cmn))
    F=R['TSetupFileEntry']; put('F.SourceFilename',F['str'].index('SourceFilename')); put('F.DestName',F['str'].index('DestName'))
    put('F.LocationEntry',F['fields']['LocationEntry'][0]); put('F.FileType',F['fields']['FileType'][0])
    Lf=L['fields']
    for k in ['FirstSlice','LastSlice','StartOffset','ChunkSuboffset','OriginalSize','ChunkCompressedSize','Flags']:
        put('L.'+k,Lf[k][0])
    put('L.StartOffset#',Lf['StartOffset'][1])
    for h in ['SHA256Sum','SHA1Sum','MD5Sum','CRC']:
        if h in Lf: put('L.hash',h); put('L.hashOff',Lf[h][0]); break
    ts='TimeStamp' if 'TimeStamp' in Lf else 'SourceTimeStamp'; put('L.TimeStamp',Lf[ts][0])
    fb=Lf['Flags'][2]
    for nm in ['ChunkCompressed','ChunkEncrypted','CallInstructionOptimized','TimeStampInUTC']:
        idx=[i for i,x in enumerate(fb) if x[2:] in (nm,) or x[3:]==nm]
        put('L.bit.'+nm, idx[0] if idx else -1)
    put('L.FlagsSize',Lf['Flags'][1])
    put('ldr',R['TSetupLdrOffsetTable']['bin'])
    put('slice',R['TDiskSliceHeader']['bin'])
    put('enchdr',R['TSetupEncryptionHeader']['bin'] if 'TSetupEncryptionHeader' in R else 0)
    sid=re.search(r"DiskSliceID:\s*TDiskSliceID\s*=\s*'([^']*)'",src).group(1); put('sliceid',sid)
    return o['id'],'|'.join(kv)
def emit():
    rows=[]
    for tag in TAGS:
        for u in ([False,True] if tag.startswith('is-5') else [True]):
            rows.append(emit_one(tag,u))
    return rows

JAVA_HEAD = '/*\n * Copyright 2026 Stephane Bury\n * SPDX-License-Identifier: Apache-2.0\n */\npackage io.github.realburst.arcana.plugin.innosetup;\n\nimport java.util.HashMap;\nimport java.util.Map;\n\n/**\n * Binary layouts of the Inno Setup "setup-0" records, one row per format\n * version (the SetupID string at the start of the setup data).\n *\n * <p>GENERATED by tools/gen_layouts.py from the record declarations of the\n * Inno Setup sources (Struct.pas / Shared.Struct.pas, one release per format\n * version): do not edit by hand, run the script again to add a version.</p>\n *\n * <p>Keys: "H", "Language", "File"... = number of String, AnsiString and\n * binary bytes of a record ("28.4.157"); "H.x" / "F.x" / "L.x" = offset of\n * field x in the binary part of the setup header, file entry or file location\n * entry; "x.bit.y" = bit number of flag y; "u" = Unicode strings; "stored" =\n * size of the block size field; "ldr" = size of the loader offset table;\n * "slice" = size of a disk slice header after its id; "enchdr" = size of the\n * encryption header (0: none); "cm" = compression methods in enum order.</p>\n */\nfinal class InnoLayouts {\n\n    private InnoLayouts() {\n    }\n\n    /** SetupID, layout: pairs of strings. */\n    private static final String[] ROWS = {\n'
JAVA_TAIL = '    };\n\n    /** Returns the layout of a format version, or null if it is not known. */\n    static Map<String, String> get(final String setupId) {\n        for (int i = 0; i < ROWS.length; i += 2) {\n            if (!ROWS[i].equals(setupId)) continue;\n            final Map<String, String> m = new HashMap<String, String>();\n            for (final String kv : ROWS[i + 1].split("\\\\|")) {\n                final int eq = kv.indexOf(\'=\');\n                m.put(kv.substring(0, eq), kv.substring(eq + 1));\n            }\n            return m;\n        }\n        return null;\n    }\n\n    /** Oldest and newest supported versions, for messages. */\n    static String range() {\n        return ROWS[0].replace("Inno Setup Setup Data ", "") + " to " + ROWS[ROWS.length - 2].replace("Inno Setup Setup Data ", "");\n    }\n}\n'


def main():
    global REPO
    if len(sys.argv) != 2:
        sys.exit('usage: gen_layouts.py <issrc clone>')
    REPO = sys.argv[1]
    out = [JAVA_HEAD]
    for i, r in emit():
        out.append('        "%s",\n        "%s",\n' % (i, r))
    out.append(JAVA_TAIL)
    sys.stdout.write(''.join(out))


if __name__ == '__main__':
    main()
