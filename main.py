import threading,jwt,json,requests,socket,os,sys,time
from time import sleep
from google.protobuf.timestamp_pb2 import Timestamp
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
import urllib3
from flask import Flask,request,jsonify
import logging
from datetime import datetime
from protobuf_decoder.protobuf_decoder import Parser
import base64,binascii,re,psutil
import MajorLoginRes_pb2
from important_zitado import*
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO,format='%(asctime)s - %(levelname)s - %(message)s',handlers=[logging.FileHandler("bot_activity.log"),logging.StreamHandler(sys.stdout)])
tempid=None;sent_inv=False;start_par=False;pleaseaccept=False;nameinv="none";idinv=0;senthi=False;statusinfo=False;statusinfo1=False;tempdata1=None;tempdata=None;leaveee=False;leaveee1=False;data22=None;isroom=False;isroom2=False;socket_client=None;clients=None;api_status_responses={};api_status_lock=threading.Lock()
def encrypt_packet(plain_text,key,iv):
    plain_text=bytes.fromhex(plain_text);cipher=AES.new(key,AES.MODE_CBC,iv);cipher_text=cipher.encrypt(pad(plain_text,AES.block_size));return cipher_text.hex()
def get_player_status(packet):
    json_result=get_available_room(packet);parsed_data=json.loads(json_result)
    if "5" not in parsed_data or "data" not in parsed_data["5"]:return "OFFLINE"
    json_data=parsed_data["5"]["data"]
    if "1" not in json_data or "data" not in json_data["1"]:return "OFFLINE"
    data=json_data["1"]["data"]
    if "3" not in data:return "OFFLINE"
    status_data=data["3"]
    if "data" not in status_data:return "OFFLINE"
    status=status_data["data"]
    if status==1:return "SOLO"
    if status==2:
        if "9" in data and "data" in data["9"]:
            group_count=data["9"]["data"];countmax1=data["10"]["data"];countmax=countmax1+1;return f"INSQUAD ({group_count}/{countmax})"
        return "INSQUAD"
    if status in [3,5]:return "INGAME"
    if status==4:return "IN ROOM"
    if status in [6,7]:return "IN SOCIAL ISLAND MODE .."
    return "NOTFOUND"
def get_idroom_by_idplayer(packet):
    json_result=get_available_room(packet);parsed_data=json.loads(json_result);json_data=parsed_data["5"]["data"];data=json_data["1"]["data"];idroom=data['15']["data"];return idroom
def get_leader(packet):
    json_result=get_available_room(packet);parsed_data=json.loads(json_result);json_data=parsed_data["5"]["data"];data=json_data["1"]["data"];leader=data['8']["data"];return leader
def fix_num(num):
    fixed="";count=0;num_str=str(num)
    for char in num_str:
        if char.isdigit():count+=1
        fixed+=char
        if count==3:fixed+="[c]";count=0
    return fixed
def Encrypt(number):
    number=int(number);encoded_bytes=[]
    while True:
        byte=number&0x7F;number>>=7
        if number:byte|=0x80
        encoded_bytes.append(byte)
        if not number:break
    return bytes(encoded_bytes).hex()
def get_available_room(input_text):
    try:
        if not input_text or len(input_text)==0:logging.error("get_available_room: Empty input_text");return None
        parsed_results=Parser().parse(input_text);parsed_results_objects=parsed_results;parsed_results_dict=parse_results(parsed_results_objects);json_data=json.dumps(parsed_results_dict);return json_data
    except Exception as e:logging.error(f"get_available_room error: {e}");import traceback;logging.error(traceback.format_exc());return None
def parse_results(parsed_results):
    result_dict={}
    for result in parsed_results:
        field_data={};field_data["wire_type"]=result.wire_type
        if result.wire_type=="varint":field_data["data"]=result.data
        if result.wire_type=="string":field_data["data"]=result.data
        if result.wire_type=="bytes":field_data["data"]=result.data
        elif result.wire_type=="length_delimited":field_data["data"]=parse_results(result.data.results)
        result_dict[result.field]=field_data
    return result_dict
def dec_to_hex(ask):
    ask_result=hex(ask);final_result=str(ask_result)[2:]
    if len(final_result)==1:final_result="0"+final_result
    return final_result
def encrypt_api(plain_text):
    plain_text=bytes.fromhex(plain_text);key=bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56]);iv=bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37]);cipher=AES.new(key,AES.MODE_CBC,iv);cipher_text=cipher.encrypt(pad(plain_text,AES.block_size));return cipher_text.hex()
def restart_program():
    logging.warning("Initiating bot restart...")
    try:
        p=psutil.Process(os.getpid())
        for handler in p.open_files()+p.connections():
            try:os.close(handler.fd)
            except Exception as e:logging.error(f"Failed to close handler {handler.fd}: {e}")
    except Exception as e:logging.error(f"Error during pre-restart cleanup: {e}")
    python=sys.executable;os.execl(python,python,*sys.argv)
class FF_CLIENT(threading.Thread):
    def __init__(self,id,password):
        super().__init__();self.id=id;self.password=password;self.key=None;self.iv=None;self.stop_flag=threading.Event();self.sockf1_thread=None;self.start_time=time.time()
    def parse_my_message(self,serialized_data):
        try:
            MajorLogRes=MajorLoginRes_pb2.MajorLoginRes();MajorLogRes.ParseFromString(serialized_data);key=MajorLogRes.ak;iv=MajorLogRes.aiv
            if isinstance(key,bytes):key=key.hex()
            if isinstance(iv,bytes):iv=iv.hex()
            self.key=key;self.iv=iv;return self.key,self.iv
        except Exception as e:logging.error(f"{e}");return None,None
    def nmnmmmmn(self,data):
        key,iv=self.key,self.iv
        try:
            key=key if isinstance(key,bytes) else bytes.fromhex(key);iv=iv if isinstance(iv,bytes) else bytes.fromhex(iv);data=bytes.fromhex(data);cipher=AES.new(key,AES.MODE_CBC,iv);cipher_text=cipher.encrypt(pad(data,AES.block_size));return cipher_text.hex()
        except Exception as e:logging.error(f"Error in nmnmmmmn: {e}")
    def createpacketinfo(self,idddd):
        ida=Encrypt(idddd);packet=f"080112090A05{ida}1005";header_lenth=len(encrypt_packet(packet,self.key,self.iv))//2;header_lenth_final=dec_to_hex(header_lenth)
        if len(header_lenth_final)==2:final_packet="0F15000000"+header_lenth_final+self.nmnmmmmn(packet)
        elif len(header_lenth_final)==3:final_packet="0F1500000"+header_lenth_final+self.nmnmmmmn(packet)
        elif len(header_lenth_final)==4:final_packet="0F150000"+header_lenth_final+self.nmnmmmmn(packet)
        elif len(header_lenth_final)==5:final_packet="0F15000"+header_lenth_final+self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def check_player_status_api(self,player_id):
        global socket_client,statusinfo,statusinfo1,tempdata,tempdata1,data22,api_status_responses,api_status_lock
        try:
            max_wait=5;wait_time=0
            while not socket_client and wait_time<max_wait:sleep(0.5);wait_time+=0.5
            if not socket_client:return {"error":"Socket not available - client may still be connecting. Please wait a few seconds and try again."}
            if not player_id:return {"error":"Please enter a player ID!"}
            with api_status_lock:
                if str(player_id) in api_status_responses:del api_status_responses[str(player_id)]
            packetmaker=self.createpacketinfo(player_id);socket_client.send(packetmaker);statusinfo1=True;timeout=10;start_time=time.time();response_data=None
            while statusinfo1 and (time.time()-start_time<timeout):
                with api_status_lock:
                    if str(player_id) in api_status_responses:
                        response_data=api_status_responses[str(player_id)].copy();del api_status_responses[str(player_id)];statusinfo=False;statusinfo1=False;break
                if statusinfo==True:
                    clean_status=None;room_id=None;leader_id=None
                    if tempdata:
                        lines=tempdata.split('\n')
                        for line in lines:
                            if line.startswith('status :'):clean_status=line.replace('status :','').strip()
                            elif line.startswith('id room :'):room_id=line.replace('id room :','').strip().replace('[c]','')
                            elif line.startswith('leader id :'):leader_id=line.replace('leader id :','').strip().replace('[c]','')
                    if clean_status:
                        response_data={"player_id":str(player_id),"status":clean_status}
                        if room_id:response_data["room_id"]=room_id
                        if leader_id:response_data["leader_id"]=leader_id
                    else:response_data={"player_id":str(player_id),"status":tempdata.replace('[c]','') if tempdata else "UNKNOWN"}
                    tempdata=None;tempdata1=None;statusinfo=False;statusinfo1=False;break
                sleep(0.1)
            if response_data:return response_data
            else:return {"error":"Timeout waiting for response","player_id":str(player_id)}
        except Exception as e:logging.error(f"Error in check_player_status_api: {e}");import traceback;logging.error(traceback.format_exc());return {"error":str(e)}
    def sockf1(self,tok,online_ip,online_port,packet,key,iv):
        global socket_client,statusinfo,tempdata,data22,api_status_lock
        socket_client=socket.socket(socket.AF_INET,socket.SOCK_STREAM);online_port=int(online_port);socket_client.connect((online_ip,online_port));socket_client.send(bytes.fromhex(tok));socket_client.settimeout(1.0)
        while not self.stop_flag.is_set():
            try:
                if time.time()-self.start_time>600:restart_program()
                data2=socket_client.recv(9999)
                if "0f00" in data2.hex()[0:4]:
                    packett=f'08{data2.hex().split("08",1)[1]}';kk=get_available_room(packett);parsed_data=json.loads(kk);asdj=parsed_data["2"]["data"];tempdata=get_player_status(packett)
                    if asdj==15:
                        if tempdata=="OFFLINE":
                            tempdata=f"The id is {tempdata}"
                            try:
                                idplayer=parsed_data["5"]["data"]["1"]["data"]["1"]["data"]
                                with api_status_lock:api_status_responses[str(idplayer)]={"player_id":str(idplayer),"status":"OFFLINE","message":tempdata}
                            except:pass
                        else:
                            idplayer=parsed_data["5"]["data"]["1"]["data"]["1"]["data"];idplayer1=fix_num(idplayer);status_result={"player_id":str(idplayer),"status":tempdata}
                            if tempdata=="IN ROOM":
                                idrooom=get_idroom_by_idplayer(packett);idrooom1=fix_num(idrooom);tempdata=f"id : {idplayer1}\nstatus : {tempdata}\nid room : {idrooom1}";data22=packett;status_result["room_id"]=str(idrooom)
                            if "INSQUAD" in tempdata:
                                idleader=get_leader(packett);idleader1=fix_num(idleader);tempdata=f"id : {idplayer1}\nstatus : {tempdata}\nleader id : {idleader1}";status_result["leader_id"]=str(idleader)
                            else:tempdata=f"id : {idplayer1}\nstatus : {tempdata}"
                            with api_status_lock:api_status_responses[str(idplayer)]=status_result
                        statusinfo=True
                if data2==b"":break
            except socket.timeout:continue
            except Exception as e:
                if not self.stop_flag.is_set():logging.error(f"Error in sockf1 loop: {e}.")
                break
        try:
            if socket_client:socket_client.close()
        except:pass
    def connect(self,tok,packet,key,iv,whisper_ip,whisper_port,online_ip,online_port):
        global clients
        clients=socket.socket(socket.AF_INET,socket.SOCK_STREAM);clients.connect((whisper_ip,whisper_port));clients.send(bytes.fromhex(tok))
        self.sockf1_thread=threading.Thread(target=self.sockf1,args=(tok,online_ip,online_port,"anything",key,iv));self.sockf1_thread.start();clients.settimeout(1.0)
        while not self.stop_flag.is_set():
            try:
                data=clients.recv(9999)
                if data==b"":break
            except socket.timeout:continue
            except Exception as e:
                if not self.stop_flag.is_set():logging.error(f"Error in connect loop: {e}.")
                break
        try:
            if clients:clients.close()
        except:pass
    def GET_PAYLOAD_BY_DATA(self,JWT_TOKEN,NEW_ACCESS_TOKEN,date):
        token_payload_base64=JWT_TOKEN.split('.')[1];token_payload_base64+='='*((4-len(token_payload_base64)%4)%4);decoded_payload=base64.urlsafe_b64decode(token_payload_base64).decode('utf-8');decoded_payload=json.loads(decoded_payload);NEW_EXTERNAL_ID=decoded_payload['external_id'];SIGNATURE_MD5=decoded_payload['signature_md5'];now=datetime.now();now=str(now)[:len(str(now))-7];formatted_time=date
        payload=bytes.fromhex("1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131382e31422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033")
        payload=payload.replace(b"2025-07-30 11:02:51",str(now).encode());payload=payload.replace(b"ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a",NEW_ACCESS_TOKEN.encode("UTF-8"));payload=payload.replace(b"996a629dbcdb3964be6b6978f5d814db",NEW_EXTERNAL_ID.encode("UTF-8"));payload=payload.replace(b"7428b253defc164018c604a1ebbfebdf",SIGNATURE_MD5.encode("UTF-8"));PAYLOAD=payload.hex();PAYLOAD=encrypt_api(PAYLOAD);PAYLOAD=bytes.fromhex(PAYLOAD);whisper_ip,whisper_port,online_ip,online_port=self.GET_LOGIN_DATA(JWT_TOKEN,PAYLOAD);return whisper_ip,whisper_port,online_ip,online_port
    def GET_LOGIN_DATA(self,JWT_TOKEN,PAYLOAD):
        url="https://client.ind.freefiremobile.com/GetLoginData";headers={'Expect':'100-continue','Authorization':f'Bearer {JWT_TOKEN}','X-Unity-Version':'2018.4.11f1','X-GA':'v1 1','ReleaseVersion':'Ob51','Content-Type':'application/x-www-form-urlencoded','User-Agent':'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)','Host':'clientbp.ggblueshark.com','Connection':'close','Accept-Encoding':'gzip, deflate, br',};max_retries=3;attempt=0
        while attempt<max_retries:
            try:
                response=requests.post(url,headers=headers,data=PAYLOAD,verify=False);response.raise_for_status();response_data=response.content;logging.info(f"Raw response length: {len(response_data)}, Content-Encoding: {response.headers.get('Content-Encoding','None')}")
                if response.headers.get('Content-Encoding')=='gzip':
                    try:import gzip;response_data=gzip.decompress(response_data)
                    except Exception as e:pass
                if len(response_data)>0 and response_data[0:2]==b'\x1f\x8b':
                    try:import gzip;response_data=gzip.decompress(response_data)
                    except Exception as e:pass
                x=response_data.hex();json_result=get_available_room(x)
                if not json_result:logging.error(f"get_available_room returned None or empty. Response hex: {x[:200]}");attempt+=1;time.sleep(2);continue
                parsed_data=json.loads(json_result)
                if not parsed_data or len(parsed_data)==0:logging.error(f"Parsed data is empty. JSON result: {json_result[:500] if json_result else 'None'}");logging.error(f"Response status: {response.status_code}, Content length: {len(response.content)}");attempt+=1;time.sleep(2);continue
                if '32' not in parsed_data or 'data' not in parsed_data['32']:logging.error(f"Missing '32' key in parsed_data. Available keys: {list(parsed_data.keys())}");attempt+=1;time.sleep(2);continue
                if '14' not in parsed_data or 'data' not in parsed_data['14']:logging.error(f"Missing '14' key in parsed_data. Available keys: {list(parsed_data.keys())}");attempt+=1;time.sleep(2);continue
                whisper_address=parsed_data['32']['data'];online_address=parsed_data['14']['data'];online_ip=online_address[:len(online_address)-6];whisper_ip=whisper_address[:len(whisper_address)-6];online_port=int(online_address[len(online_address)-5:]);whisper_port=int(whisper_address[len(whisper_address)-5:]);return whisper_ip,whisper_port,online_ip,online_port
            except KeyError as e:logging.error(f"KeyError: Missing key {e} in parsed_data. Available keys: {list(parsed_data.keys()) if 'parsed_data' in locals() else 'N/A'}. Attempt {attempt+1} of {max_retries}. Retrying...");attempt+=1;time.sleep(2)
            except requests.RequestException as e:logging.error(f"Request failed: {e}. Attempt {attempt+1} of {max_retries}. Retrying...");attempt+=1;time.sleep(2)
            except Exception as e:logging.error(f"Unexpected error: {e}. Attempt {attempt+1} of {max_retries}. Retrying...");attempt+=1;time.sleep(2)
        logging.critical("Failed to get login data after multiple attempts. Restarting.");restart_program();return None,None
    def guest_token(self,uid,password):
        url="https://100067.connect.garena.com/oauth/guest/token/grant";headers={"Host":"100067.connect.garena.com","User-Agent":"GarenaMSDK/4.0.19P4(G011A ;Android 10;en;EN;)","Content-Type":"application/x-www-form-urlencoded","Accept-Encoding":"gzip, deflate, br","Connection":"close",};data={"uid":f"{uid}","password":f"{password}","response_type":"token","client_type":"2","client_secret":"2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3","client_id":"100067",};response=requests.post(url,headers=headers,data=data);data=response.json();NEW_ACCESS_TOKEN=data['access_token'];NEW_OPEN_ID=data['open_id'];OLD_ACCESS_TOKEN="ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a";OLD_OPEN_ID="996a629dbcdb3964be6b6978f5d814db";time.sleep(0.2);data=self.TOKEN_MAKER(OLD_ACCESS_TOKEN,NEW_ACCESS_TOKEN,OLD_OPEN_ID,NEW_OPEN_ID,uid);return(data)
    def TOKEN_MAKER(self,OLD_ACCESS_TOKEN,NEW_ACCESS_TOKEN,OLD_OPEN_ID,NEW_OPEN_ID,id):
        headers={'X-Unity-Version':'2018.4.11f1','ReleaseVersion':'Ob51','Content-Type':'application/x-www-form-urlencoded','X-GA':'v1 1','Content-Length':'928','User-Agent':'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)','Host':'loginbp.ggblueshark.com','Connection':'Keep-Alive','Accept-Encoding':'gzip'};data=bytes.fromhex('1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131382e31422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033');data=data.replace(OLD_OPEN_ID.encode(),NEW_OPEN_ID.encode());data=data.replace(OLD_ACCESS_TOKEN.encode(),NEW_ACCESS_TOKEN.encode());hex=data.hex();d=encrypt_api(data.hex());Final_Payload=bytes.fromhex(d);URL="https://loginbp.ggblueshark.com/MajorLogin";RESPONSE=requests.post(URL,headers=headers,data=Final_Payload,verify=False)
        MajorLogRes=MajorLoginRes_pb2.MajorLoginRes();MajorLogRes.ParseFromString(RESPONSE.content);timestamp=MajorLogRes.kts;key=MajorLogRes.ak;iv=MajorLogRes.aiv;BASE64_TOKEN=MajorLogRes.token;timestamp_obj=Timestamp();timestamp_obj.FromNanoseconds(timestamp);timestamp_seconds=timestamp_obj.seconds;timestamp_nanos=timestamp_obj.nanos;combined_timestamp=timestamp_seconds*1_000_000_000+timestamp_nanos
        if RESPONSE.status_code==200:
            if len(RESPONSE.text)<10:return False
            whisper_ip,whisper_port,online_ip,online_port=self.GET_PAYLOAD_BY_DATA(BASE64_TOKEN,NEW_ACCESS_TOKEN,1);self.key=key;self.iv=iv;return (BASE64_TOKEN,key,iv,combined_timestamp,whisper_ip,whisper_port,online_ip,online_port)
        else:return False
    def get_tok(self):
        global g_token
        token_data=self.guest_token(self.id,self.password)
        if not token_data:logging.critical("Failed to get token data from guest_token. Restarting.");restart_program()
        token,key,iv,Timestamp,whisper_ip,whisper_port,online_ip,online_port=token_data;g_token=token
        try:decoded=jwt.decode(token,options={"verify_signature":False});account_id=decoded.get('account_id');encoded_acc=hex(account_id)[2:];hex_value=dec_to_hex(Timestamp);time_hex=hex_value;BASE64_TOKEN_=token.encode().hex()
        except Exception as e:logging.error(f"Error processing token: {e}. Restarting.");restart_program()
        try:
            head=hex(len(encrypt_packet(BASE64_TOKEN_,key,iv))//2)[2:];length=len(encoded_acc);zeros='00000000'
            if length==9:zeros='0000000'
            elif length==8:zeros='00000000'
            elif length==10:zeros='000000'
            elif length==7:zeros='000000000'
            head=f'0115{zeros}{encoded_acc}{time_hex}00000{head}';final_token=head+encrypt_packet(BASE64_TOKEN_,key,iv)
        except Exception as e:logging.error(f"Error constructing final token: {e}. Restarting.");restart_program()
        token=final_token;self.connect(token,'anything',key,iv,whisper_ip,whisper_port,online_ip,online_port);return token,key,iv
    def run(self):
        try:self.get_tok()
        except Exception as e:logging.error(f"Error in FF_CLIENT run: {e}")
    def close(self):
        global socket_client,clients
        try:
            self.stop_flag.set()
            if self.sockf1_thread and self.sockf1_thread.is_alive():self.sockf1_thread.join(timeout=2.0)
            sleep(0.2)
            try:
                if socket_client:socket_client.close()
            except Exception as e:pass
            socket_client=None
            try:
                if clients:clients.close()
            except Exception as e:pass
            clients=None
        except Exception as e:logging.error(f"Error closing FF_CLIENT: {e}")
def load_accounts():
    try:
        with open(os.path.join(os.path.dirname(__file__),'accs.json'),'r',encoding='utf-8') as file:
            data=json.load(file);accounts=[]
            for uid,value in data.items():
                if isinstance(value,dict):accounts.append((uid,value.get("password","")))
                else:accounts.append((uid,value))
            return accounts
    except Exception as e:print(f"[!] Error loading accounts: {e}");return []
flask_app=Flask(__name__);api_client_instance=None;api_client_lock=threading.Lock()
def set_api_client_instance(client):
    global api_client_instance
    with api_client_lock:api_client_instance=client
def check_player_status_api_wrapper(player_id):
    global api_client_instance
    client=None
    try:
        accounts=load_accounts()
        if not accounts:return {"error":"No accounts found in accs.json"}
        account_id,account_password=accounts[0];client=FF_CLIENT(account_id,account_password)
        with api_client_lock:api_client_instance=client
        client.start();sleep(0.5);max_wait=20;wait_time=0
        global socket_client
        client_ready=False
        while wait_time<max_wait:
            try:
                if socket_client:
                    try:
                        socket_client.getpeername()
                        if hasattr(client,'key') and client.key is not None:client_ready=True;break
                    except (OSError,AttributeError):pass
            except Exception as e:pass
            sleep(0.5);wait_time+=0.5
        if not client_ready:
            if not socket_client:return {"error":"Client connection timeout - socket not created. Please try again."}
            if not hasattr(client,'key') or client.key is None:return {"error":"Client connection timeout - not fully initialized. Please try again."}
        result=client.check_player_status_api(player_id);return result
    except Exception as e:logging.error(f"Error in check_player_status_api_wrapper: {e}");import traceback;logging.error(traceback.format_exc());return {"error":str(e)}
    finally:
        if client:
            try:
                client.close()
                with api_client_lock:
                    if api_client_instance==client:api_client_instance=None
            except Exception as e:logging.error(f"Error closing client: {e}")
@flask_app.route('/status',methods=['GET'])
def status_endpoint():
    try:
        uid=request.args.get('uid')
        if not uid:return jsonify({"success":False,"error":"Please provide a player ID (uid parameter)","example":"/status?uid=12345678"}),400
        result=check_player_status_api_wrapper(uid)
        if "error" in result:return jsonify({"success":False,"error":result["error"],"player_id":uid}),500
        return jsonify({"success":True,"data":result}),200
    except Exception as e:logging.error(f"Error in /status endpoint: {e}");return jsonify({"success":False,"error":str(e)}),500
@flask_app.route('/health',methods=['GET'])
def health_check():
    with api_client_lock:client_initialized=api_client_instance is not None
    return jsonify({"status":"ok","client_initialized":client_initialized}),200
def run_api_server(port=5000,host='0.0.0.0'):
    flask_app.run(host=host,port=port,debug=False,threaded=True)
def main():
    print("Starting Falcon Bot API Server...\n");sleep(1)
    api_thread=threading.Thread(target=run_api_server,args=(5000,'0.0.0.0'),daemon=True);api_thread.start()
    print("✅ API server started on http://0.0.0.0:5000");print("   Endpoint: /status?uid=PLAYER_ID");print("   Mode: On-demand (client starts only when request comes)\n");sleep(2)
    accounts=load_accounts()
    if not accounts:print("⚠️ No accounts found in accs.json");print("   Please add accounts to use the API\n")
    else:print(f"✅ Found {len(accounts)} account(s) ready for API requests\n")
    try:
        while True:sleep(1)
    except KeyboardInterrupt:print("\nShutting down...")
if __name__=="__main__":
    try:main()
    except Exception as e:print(f"Unhandled error occurred: {e}");restart_program()
