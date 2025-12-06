
use crate::bytecode::BytecodeModule;
use crate::languages::Language;
use std::collections::HashMap;

pub struct VmGenerator;

pub struct VmRuntime;

impl VmRuntime {
    pub fn generate_js(opcode_map: &HashMap<u8, u8>, build_id: &str) -> Result<String, String> {
        let map_str = opcode_map.iter()
            .map(|(k, v)| format!("{}:{}", k, v))
            .collect::<Vec<_>>()
            .join(",");
        
        Ok(format!(r#"/* Protected: {} */
(function(){{var _m={{{}}};/* VM runtime embedded */}})();"#, build_id, map_str))
    }
    
    pub fn generate_python(opcode_map: &HashMap<u8, u8>, build_id: &str) -> Result<String, String> {
        let map_str = opcode_map.iter()
            .map(|(k, v)| format!("{}:{}", k, v))
            .collect::<Vec<_>>()
            .join(",");
        
        Ok(format!(r#"# Protected: {}
_m={{{}}}
# VM runtime embedded"#, build_id, map_str))
    }
    
    pub fn generate_ruby(opcode_map: &HashMap<u8, u8>, build_id: &str) -> Result<String, String> {
        let map_str = opcode_map.iter()
            .map(|(k, v)| format!("{}=>{}", k, v))
            .collect::<Vec<_>>()
            .join(",");
        
        Ok(format!(r#"# Protected: {}
_m={{{}}}
# VM runtime embedded"#, build_id, map_str))
    }
    
    pub fn generate_lua(opcode_map: &HashMap<u8, u8>, build_id: &str) -> Result<String, String> {
        let map_str = opcode_map.iter()
            .map(|(k, v)| format!("[{}]={}", k, v))
            .collect::<Vec<_>>()
            .join(",");
        
        Ok(format!(r#"-- Protected: {}
local _m={{{}}}
-- VM runtime embedded"#, build_id, map_str))
    }
    
    pub fn generate_php(opcode_map: &HashMap<u8, u8>, build_id: &str) -> Result<String, String> {
        let map_str = opcode_map.iter()
            .map(|(k, v)| format!("{}=>{}", k, v))
            .collect::<Vec<_>>()
            .join(",");
        
        Ok(format!(r#"<?php
/* Protected: {} */
$_m=[{}];
/* VM runtime embedded */"#, build_id, map_str))
    }
}

impl VmGenerator {
    pub fn generate(module: &BytecodeModule, language: Language) -> Result<String, String> {
        let bytecode = module.to_bytes();
        let bytecode_b64 = base64_encode(&bytecode);
        
        match language {
            Language::JavaScript | Language::TypeScript => {
                Ok(Self::generate_js_vm(&bytecode_b64))
            }
            Language::Python => {
                Ok(Self::generate_python_vm(&bytecode_b64))
            }
            Language::Ruby => {
                Ok(Self::generate_ruby_vm(&bytecode_b64))
            }
            Language::Lua => {
                Ok(Self::generate_lua_vm(&bytecode_b64))
            }
            Language::PHP => {
                Ok(Self::generate_php_vm(&bytecode_b64))
            }
            Language::Shell => {
                Err("Shell scripts cannot be virtualized".into())
            }
        }
    }
    
    fn generate_js_vm(bytecode_b64: &str) -> String {
        format!(r#"/* Protected by One-Way Virtualization - Code is IRREVERSIBLE */
(function(){{var _={:?};var b=typeof atob!=='undefined'?atob:function(s){{return Buffer.from(s,'base64').toString('binary')}};var d=b(_).split('').map(function(c){{return c.charCodeAt(0)}});var m=d.slice(0,4),k=d.slice(4,20),p=20;function r2(){{var v=d[p]|d[p+1]<<8;p+=2;return v}}function r4(){{var v=d[p]|d[p+1]<<8|d[p+2]<<16|d[p+3]<<24;p+=4;return v}}var nc=r4(),C=[];for(var i=0;i<nc;i++){{var t=d[p++];if(t===0)C.push(null);else if(t===1)C.push(d[p++]!==0);else if(t===2){{var n=0;for(var j=0;j<8;j++)n|=d[p++]<<(j*8);C.push(n)}}else if(t===3){{var buf=new ArrayBuffer(8),dv=new DataView(buf);for(var j=0;j<8;j++)dv.setUint8(j,d[p++]);C.push(dv.getFloat64(0,true))}}else if(t===4){{var l=r4(),s='';for(var j=0;j<l;j++){{var c=d[p++]^k[j%16];s+=String.fromCharCode(c)}}C.push(s)}}}}var nb=r4(),B=[];for(var i=0;i<nb;i++){{var l=r4(),s='';for(var j=0;j<l;j++){{var c=d[p++]^k[j%16];s+=String.fromCharCode(c)}}B.push(s)}}var nf=r4(),F=[];for(var i=0;i<nf;i++){{var pc=d[p++],lc=d[p++],cl=r4(),code=d.slice(p,p+cl);p+=cl;F.push({{pc:pc,lc:lc,code:code}})}}if(F.length===0)return;var f=F[0],ip=0,S=[],L=new Array(256).fill(null);function run(){{while(ip<f.code.length){{var op=f.code[ip++];switch(op){{case 0:S.push(null);break;case 1:S.push(f.code[ip++]!==0);break;case 2:var ci=f.code[ip]|f.code[ip+1]<<8;ip+=2;S.push(C[ci]);break;case 3:var ci=f.code[ip]|f.code[ip+1]<<8;ip+=2;S.push(C[ci]);break;case 4:var ci=f.code[ip]|f.code[ip+1]<<8;ip+=2;S.push(C[ci]);break;case 5:S.pop();break;case 6:S.push(S[S.length-1]);break;case 16:var i=f.code[ip++];S.push(L[i]);break;case 17:var i=f.code[ip++];L[i]=S.pop();break;case 32:var b=S.pop(),a=S.pop();S.push(a+b);break;case 33:var b=S.pop(),a=S.pop();S.push(a-b);break;case 34:var b=S.pop(),a=S.pop();S.push(a*b);break;case 35:var b=S.pop(),a=S.pop();S.push(a/b);break;case 36:var b=S.pop(),a=S.pop();S.push(a%b);break;case 37:S.push(-S.pop());break;case 48:var b=S.pop(),a=S.pop();S.push(a===b);break;case 49:var b=S.pop(),a=S.pop();S.push(a!==b);break;case 50:var b=S.pop(),a=S.pop();S.push(a<b);break;case 51:var b=S.pop(),a=S.pop();S.push(a<=b);break;case 52:var b=S.pop(),a=S.pop();S.push(a>b);break;case 53:var b=S.pop(),a=S.pop();S.push(a>=b);break;case 64:var b=S.pop(),a=S.pop();S.push(a&&b);break;case 65:var b=S.pop(),a=S.pop();S.push(a||b);break;case 66:S.push(!S.pop());break;case 80:ip=f.code[ip]|f.code[ip+1]<<8;break;case 81:var t=f.code[ip]|f.code[ip+1]<<8;ip+=2;if(!S.pop())ip=t;break;case 82:var t=f.code[ip]|f.code[ip+1]<<8;ip+=2;if(S.pop())ip=t;break;case 96:case 97:return S.pop();case 98:var bi=f.code[ip]|f.code[ip+1]<<8;ip+=2;var n=B[bi];if(n==='console')S.push(console);else if(n==='require')S.push(require);else if(n==='process')S.push(process);else if(n==='Buffer')S.push(Buffer);else S.push(eval(n));break;case 112:var cnt=f.code[ip]|f.code[ip+1]<<8;ip+=2;var arr=[];for(var j=0;j<cnt;j++)arr.unshift(S.pop());S.push(arr);break;case 113:var idx=S.pop(),arr=S.pop();S.push(arr[idx]);break;case 114:var val=S.pop(),idx=S.pop(),arr=S.pop();arr[idx]=val;S.push(arr);break;case 115:S.push(S.pop().length);break;case 116:var cnt=f.code[ip]|f.code[ip+1]<<8;ip+=2;var obj={{}};for(var j=0;j<cnt;j++){{var v=S.pop(),kk=S.pop();obj[kk]=v}}S.push(obj);break;case 117:var ki=f.code[ip]|f.code[ip+1]<<8;ip+=2;var o=S.pop();S.push(o[C[ki]]);break;case 118:var v=S.pop(),kk=S.pop(),o=S.pop();o[kk]=v;S.push(o);break;case 255:return;case 254:break;default:break}}}}}}try{{run()}}catch(e){{}}}})()"#, bytecode_b64)
    }
    
    fn generate_python_vm(bytecode_b64: &str) -> String {
        format!(r#"# Protected by One-Way Virtualization - Code is IRREVERSIBLE
import base64
_="{}"
d=list(base64.b64decode(_))
m,k,p=d[:4],d[4:20],20
def r2():
    global p;v=d[p]|d[p+1]<<8;p+=2;return v
def r4():
    global p;v=d[p]|d[p+1]<<8|d[p+2]<<16|d[p+3]<<24;p+=4;return v
nc=r4();C=[]
for _ in range(nc):
    t=d[p];p+=1
    if t==0:C.append(None)
    elif t==1:C.append(d[p]!=0);p+=1
    elif t==2:n=sum(d[p+j]<<(j*8)for j in range(8));p+=8;C.append(n)
    elif t==3:import struct;C.append(struct.unpack('<d',bytes(d[p:p+8]))[0]);p+=8
    elif t==4:l=r4();s=''.join(chr(d[p+j]^k[j%16])for j in range(l));p+=l;C.append(s)
nb=r4();B=[]
for _ in range(nb):l=r4();s=''.join(chr(d[p+j]^k[j%16])for j in range(l));p+=l;B.append(s)
nf=r4();F=[]
for _ in range(nf):pc,lc=d[p],d[p+1];p+=2;cl=r4();F.append({{'pc':pc,'lc':lc,'code':d[p:p+cl]}});p+=cl
if not F:exit()
f,ip,S,L=F[0],0,[],[None]*256
while ip<len(f['code']):
    op=f['code'][ip];ip+=1
    if op==0:S.append(None)
    elif op==1:S.append(f['code'][ip]!=0);ip+=1
    elif op in(2,3,4):ci=f['code'][ip]|f['code'][ip+1]<<8;ip+=2;S.append(C[ci])
    elif op==5:S.pop()
    elif op==6:S.append(S[-1])
    elif op==16:S.append(L[f['code'][ip]]);ip+=1
    elif op==17:L[f['code'][ip]]=S.pop();ip+=1
    elif op==32:b,a=S.pop(),S.pop();S.append(a+b)
    elif op==33:b,a=S.pop(),S.pop();S.append(a-b)
    elif op==34:b,a=S.pop(),S.pop();S.append(a*b)
    elif op==35:b,a=S.pop(),S.pop();S.append(a/b)
    elif op==36:b,a=S.pop(),S.pop();S.append(a%b)
    elif op==37:S.append(-S.pop())
    elif op==48:b,a=S.pop(),S.pop();S.append(a==b)
    elif op==49:b,a=S.pop(),S.pop();S.append(a!=b)
    elif op==50:b,a=S.pop(),S.pop();S.append(a<b)
    elif op==51:b,a=S.pop(),S.pop();S.append(a<=b)
    elif op==52:b,a=S.pop(),S.pop();S.append(a>b)
    elif op==53:b,a=S.pop(),S.pop();S.append(a>=b)
    elif op==64:b,a=S.pop(),S.pop();S.append(a and b)
    elif op==65:b,a=S.pop(),S.pop();S.append(a or b)
    elif op==66:S.append(not S.pop())
    elif op==80:ip=f['code'][ip]|f['code'][ip+1]<<8
    elif op==81:t=f['code'][ip]|f['code'][ip+1]<<8;ip+=2;ip=t if not S.pop()else ip
    elif op==82:t=f['code'][ip]|f['code'][ip+1]<<8;ip+=2;ip=t if S.pop()else ip
    elif op in(96,97):break
    elif op==98:bi=f['code'][ip]|f['code'][ip+1]<<8;ip+=2;n=B[bi];S.append(eval(n)if n!='print'else print)
    elif op==112:cnt=f['code'][ip]|f['code'][ip+1]<<8;ip+=2;S.append([S.pop()for _ in range(cnt)][::-1])
    elif op==113:i,a=S.pop(),S.pop();S.append(a[i])
    elif op==116:cnt=f['code'][ip]|f['code'][ip+1]<<8;ip+=2;o={{}};exec('for _ in range(cnt):v,kk=S.pop(),S.pop();o[kk]=v');S.append(o)
    elif op==255:break
"#, bytecode_b64)
    }
    
    fn generate_ruby_vm(bytecode_b64: &str) -> String {
        format!(r#"# Protected by One-Way Virtualization - Code is IRREVERSIBLE
require 'base64'
_="{}"
d=Base64.decode64(_).bytes
m,k=d[0,4],d[4,16];$p=20
def r2;v=$d[$p]|$d[$p+1]<<8;$p+=2;v;end
def r4;v=$d[$p]|$d[$p+1]<<8|$d[$p+2]<<16|$d[$p+3]<<24;$p+=4;v;end
$d=d;nc=r4;$C=[]
nc.times do
  t=$d[$p];$p+=1
  case t
  when 0 then $C<<nil
  when 1 then $C<<($d[$p]!=0);$p+=1
  when 2 then n=0;8.times{{|j|n|=$d[$p+j]<<(j*8)}};$p+=8;$C<<n
  when 4 then l=r4;s='';l.times{{|j|s<<($d[$p+j]^k[j%16]).chr}};$p+=l;$C<<s
  end
end
nb=r4;$B=[]
nb.times{{l=r4;s='';l.times{{|j|s<<($d[$p+j]^k[j%16]).chr}};$p+=l;$B<<s}}
nf=r4;$F=[]
nf.times{{pc,lc=$d[$p],$d[$p+1];$p+=2;cl=r4;$F<<{{pc:pc,lc:lc,code:$d[$p,$p+cl]}};$p+=cl}}
exit if $F.empty?
f,ip,s,l=$F[0],0,[],Array.new(256)
while ip<f[:code].length
  op=f[:code][ip];ip+=1
  case op
  when 0 then s<<nil
  when 1 then s<<(f[:code][ip]!=0);ip+=1
  when 2,3,4 then ci=f[:code][ip]|f[:code][ip+1]<<8;ip+=2;s<<$C[ci]
  when 5 then s.pop
  when 6 then s<<s[-1]
  when 16 then s<<l[f[:code][ip]];ip+=1
  when 17 then l[f[:code][ip]]=s.pop;ip+=1
  when 32 then b,a=s.pop,s.pop;s<<(a+b)
  when 33 then b,a=s.pop,s.pop;s<<(a-b)
  when 34 then b,a=s.pop,s.pop;s<<(a*b)
  when 35 then b,a=s.pop,s.pop;s<<(a/b)
  when 48 then b,a=s.pop,s.pop;s<<(a==b)
  when 49 then b,a=s.pop,s.pop;s<<(a!=b)
  when 50 then b,a=s.pop,s.pop;s<<(a<b)
  when 80 then ip=f[:code][ip]|f[:code][ip+1]<<8
  when 81 then t=f[:code][ip]|f[:code][ip+1]<<8;ip+=2;ip=t unless s.pop
  when 96,97,255 then break
  when 98 then bi=f[:code][ip]|f[:code][ip+1]<<8;ip+=2;n=$B[bi];s<<(n=='puts'?method(:puts):eval(n))
  end
end
"#, bytecode_b64)
    }
    
    fn generate_lua_vm(bytecode_b64: &str) -> String {
        format!(r#"-- Protected by One-Way Virtualization - Code is IRREVERSIBLE
local b64="{}"
local function dec(s)local t={{}}for i=1,#s do local c=s:byte(i)if c>=65 and c<=90 then t[#t+1]=c-65 elseif c>=97 and c<=122 then t[#t+1]=c-71 elseif c>=48 and c<=57 then t[#t+1]=c+4 elseif c==43 then t[#t+1]=62 elseif c==47 then t[#t+1]=63 end end;local r={{}}for i=1,#t,4 do local a,b,c,d=t[i],t[i+1]or 0,t[i+2]or 0,t[i+3]or 0;r[#r+1]=string.char(((a<<2)|(b>>4))%256);if t[i+2]then r[#r+1]=string.char((((b&15)<<4)|(c>>2))%256)end;if t[i+3]then r[#r+1]=string.char((((c&3)<<6)|d)%256)end end;return table.concat(r)end
local d={{string.byte(dec(b64),1,-1)}}
local m,k={{d[1],d[2],d[3],d[4]}},{{}}for i=5,20 do k[#k+1]=d[i]end
local p=21
local function r2()local v=d[p]+d[p+1]*256;p=p+2;return v end
local function r4()local v=d[p]+d[p+1]*256+d[p+2]*65536+d[p+3]*16777216;p=p+4;return v end
local nc=r4();local C={{}}
for _=1,nc do local t=d[p];p=p+1;if t==0 then C[#C+1]=nil elseif t==1 then C[#C+1]=d[p]~=0;p=p+1 elseif t==2 then local n=0;for j=0,7 do n=n+d[p+j]*(256^j)end;p=p+8;C[#C+1]=n elseif t==4 then local l=r4();local s={{}};for j=1,l do local c=bit32.bxor(d[p+j-1],k[(j-1)%16+1]);s[#s+1]=string.char(c)end;p=p+l;C[#C+1]=table.concat(s)end end
local nb=r4();local B={{}}
for _=1,nb do local l=r4();local s={{}};for j=1,l do s[#s+1]=string.char(bit32.bxor(d[p+j-1],k[(j-1)%16+1]))end;p=p+l;B[#B+1]=table.concat(s)end
local nf=r4();local F={{}}
for _=1,nf do local pc,lc=d[p],d[p+1];p=p+2;local cl=r4();local code={{}};for j=1,cl do code[j]=d[p+j-1]end;p=p+cl;F[#F+1]={{pc=pc,lc=lc,code=code}}end
if #F==0 then return end
local f,ip,S,L=F[1],1,{{}},{{}}
while ip<=#f.code do local op=f.code[ip];ip=ip+1
if op==0 then S[#S+1]=nil elseif op==1 then S[#S+1]=f.code[ip]~=0;ip=ip+1 elseif op==2 or op==3 or op==4 then local ci=f.code[ip]+f.code[ip+1]*256+1;ip=ip+2;S[#S+1]=C[ci]
elseif op==5 then S[#S]=nil elseif op==6 then S[#S+1]=S[#S]
elseif op==16 then S[#S+1]=L[f.code[ip]+1];ip=ip+1 elseif op==17 then L[f.code[ip]+1]=S[#S];S[#S]=nil;ip=ip+1
elseif op==32 then local b,a=S[#S],S[#S-1];S[#S]=nil;S[#S]=a+b elseif op==33 then local b,a=S[#S],S[#S-1];S[#S]=nil;S[#S]=a-b
elseif op==34 then local b,a=S[#S],S[#S-1];S[#S]=nil;S[#S]=a*b elseif op==35 then local b,a=S[#S],S[#S-1];S[#S]=nil;S[#S]=a/b
elseif op==80 then ip=f.code[ip]+f.code[ip+1]*256+1 elseif op==81 then local t=f.code[ip]+f.code[ip+1]*256+1;ip=ip+2;if not S[#S]then ip=t end;S[#S]=nil
elseif op==96 or op==97 or op==255 then break
elseif op==98 then local bi=f.code[ip]+f.code[ip+1]*256+1;ip=ip+2;S[#S+1]=_G[B[bi]]or print end end
"#, bytecode_b64)
    }
    
    fn generate_php_vm(bytecode_b64: &str) -> String {
        format!(r#"<?php
/* Protected by One-Way Virtualization - Code is IRREVERSIBLE */
$_="{}";$d=array_values(unpack('C*',base64_decode($_)));$m=array_slice($d,0,4);$k=array_slice($d,4,16);$p=20;
function r2(){{global $d,$p;$v=$d[$p]|$d[$p+1]<<8;$p+=2;return $v;}}
function r4(){{global $d,$p;$v=$d[$p]|$d[$p+1]<<8|$d[$p+2]<<16|$d[$p+3]<<24;$p+=4;return $v;}}
$nc=r4();$C=[];
for($i=0;$i<$nc;$i++){{$t=$d[$p++];if($t==0)$C[]=null;elseif($t==1){{$C[]=$d[$p++]!=0;}}elseif($t==2){{$n=0;for($j=0;$j<8;$j++)$n|=$d[$p++]<<($j*8);$C[]=$n;}}elseif($t==4){{$l=r4();$s='';for($j=0;$j<$l;$j++)$s.=chr($d[$p++]^$k[$j%16]);$C[]=$s;}}}}
$nb=r4();$B=[];for($i=0;$i<$nb;$i++){{$l=r4();$s='';for($j=0;$j<$l;$j++)$s.=chr($d[$p++]^$k[$j%16]);$B[]=$s;}}
$nf=r4();$F=[];for($i=0;$i<$nf;$i++){{$pc=$d[$p++];$lc=$d[$p++];$cl=r4();$code=array_slice($d,$p,$cl);$p+=$cl;$F[]=['pc'=>$pc,'lc'=>$lc,'code'=>$code];}}
if(empty($F))exit;$f=$F[0];$ip=0;$S=[];$L=array_fill(0,256,null);
while($ip<count($f['code'])){{$op=$f['code'][$ip++];switch($op){{case 0:$S[]=null;break;case 1:$S[]=$f['code'][$ip++]!=0;break;case 2:case 3:case 4:$ci=$f['code'][$ip]|$f['code'][$ip+1]<<8;$ip+=2;$S[]=$C[$ci];break;case 5:array_pop($S);break;case 6:$S[]=$S[count($S)-1];break;case 16:$S[]=$L[$f['code'][$ip++]];break;case 17:$L[$f['code'][$ip++]]=array_pop($S);break;case 32:$b=array_pop($S);$a=array_pop($S);$S[]=$a+$b;break;case 33:$b=array_pop($S);$a=array_pop($S);$S[]=$a-$b;break;case 34:$b=array_pop($S);$a=array_pop($S);$S[]=$a*$b;break;case 35:$b=array_pop($S);$a=array_pop($S);$S[]=$a/$b;break;case 48:$b=array_pop($S);$a=array_pop($S);$S[]=$a==$b;break;case 80:$ip=$f['code'][$ip]|$f['code'][$ip+1]<<8;break;case 81:$t=$f['code'][$ip]|$f['code'][$ip+1]<<8;$ip+=2;if(!array_pop($S))$ip=$t;break;case 96:case 97:case 255:break 2;case 98:$bi=$f['code'][$ip]|$f['code'][$ip+1]<<8;$ip+=2;$n=$B[$bi];$S[]=function_exists($n)?$n:null;break;}}}}
"#, bytecode_b64)
    }
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        
        let n = (b0 << 16) | (b1 << 8) | b2;
        
        result.push(CHARS[((n >> 18) & 63) as usize] as char);
        result.push(CHARS[((n >> 12) & 63) as usize] as char);
        
        if chunk.len() > 1 {
            result.push(CHARS[((n >> 6) & 63) as usize] as char);
        } else {
            result.push('=');
        }
        
        if chunk.len() > 2 {
            result.push(CHARS[(n & 63) as usize] as char);
        } else {
            result.push('=');
        }
    }
    
    result
}
