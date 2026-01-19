import threading,jwt,json,requests,socket,os,sys,time
from time import sleep
from google.protobuf.timestamp_pb2 import Timestamp
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
import urllib3
from flask import Flask,request,jsonify
import logging
from itertools import cycle
from datetime import datetime
from protobuf_decoder.protobuf_decoder import Parser
import base64,binascii,re,psutil
import MajorLoginRes_pb2
from important_zitado import*
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO,format='%(asctime)s - %(levelname)s - %(message)s',handlers=[logging.FileHandler("bot_activity.log"),logging.StreamHandler(sys.stdout)])
tempid=None;sent_inv=False;start_par=False;pleaseaccept=False;nameinv="none";idinv=0;senthi=False;statusinfo=False;statusinfo1=False;tempdata1=None;tempdata=None;leaveee=False;leaveee1=False;data22=None;isroom=False;isroom2=False;socket_client=None;clients=None;api_status_responses={};api_status_lock=threading.Lock()
DYNAMIC_CLAN_ID = None
DYNAMIC_CLAN_KEY = None
default_key = b'Yg&tc%DEuh6%Zc^8'
default_iv = b'6oyZDr22E3ychjM%'
freefire_version = "OB52"

def extract_clan_data_from_response(response_data):
    """Extract clan ID and clan key from server response"""
    global DYNAMIC_CLAN_ID, DYNAMIC_CLAN_KEY
    try:
        json_result = get_available_room(response_data)
        parsed_data = json.loads(json_result)
        if "20" in parsed_data and "data" in parsed_data["20"]:
            DYNAMIC_CLAN_ID = str(parsed_data["20"]["data"])
        if "55" in parsed_data and "data" in parsed_data["55"]:
            DYNAMIC_CLAN_KEY = parsed_data["55"]["data"]
        return DYNAMIC_CLAN_ID, DYNAMIC_CLAN_KEY
    except Exception as e:
        logging.error(f"Error extracting clan data: {e}")
        return None, None

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
    plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(default_key, AES.MODE_CBC, default_iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()
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
        super().__init__();self.id=id;self.password=password;self.key=None;self.iv=None;self.player_uid=None;self.clan_id=None;self.clan_key=None;self.roomid=None;self.stop_flag=threading.Event();self.sockf1_thread=None;self.start_time=time.time()
    def parse_my_message(self, serialized_data):
        try:
            MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
            MajorLogRes.ParseFromString(serialized_data)
            
            timestamp = MajorLogRes.kts
            key = MajorLogRes.ak
            iv = MajorLogRes.aiv
            BASE64_TOKEN = MajorLogRes.token
            
            timestamp_obj = Timestamp()
            timestamp_obj.FromNanoseconds(timestamp)
            timestamp_seconds = timestamp_obj.seconds
            timestamp_nanos = timestamp_obj.nanos
            combined_timestamp = timestamp_seconds * 1_000_000_000 + timestamp_nanos
            
            self.key = key
            self.iv = iv
            return combined_timestamp, key, iv, BASE64_TOKEN
        except Exception as e:
            logging.error(f"Error in parse_my_message: {e}")
            return None, None, None, None
    def nmnmmmmn(self, data):
        key = self.key if self.key else default_key
        iv = self.iv if self.iv else default_iv
        try:
            key = key if isinstance(key, bytes) else bytes.fromhex(key)
            iv = iv if isinstance(iv, bytes) else bytes.fromhex(iv)
            data = bytes.fromhex(data)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            cipher_text = cipher.encrypt(pad(data, AES.block_size))
            return cipher_text.hex()
        except Exception as e:
            logging.error(f"Error in nmnmmmmn: {e}")
            return None
    def createpacketinfo(self, idddd):
        ida = Encrypt(idddd)
        packet = f"080112090A05{ida}1005"
        header_lenth = len(encrypt_packet(packet, self.key, self.iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0F15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0F1500000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0F150000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0F15000" + header_lenth_final +  self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def check_player_status_api(self,player_id):
        global socket_client,statusinfo,statusinfo1,tempdata,tempdata1,data22,api_status_responses,api_status_lock
        try:
            max_wait=5;wait_time=0
            while (not socket_client or (socket_client and socket_client._closed)) and wait_time<max_wait:sleep(0.5);wait_time+=0.5
            if not socket_client or socket_client._closed:return {"error":"Socket not available - client may still be connecting or disconnected. Please wait a few seconds and try again."}
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
    def sockf1(self, tok, host, port, packet, key, iv):
        global socket_client, statusinfo, tempdata, data22, api_status_lock
        try:
            socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            port = int(port)
            socket_client.connect((host, port))
            socket_client.send(bytes.fromhex(tok))
            socket_client.settimeout(1.0)
        except Exception as e:
            logging.error(f"Error connecting socket in sockf1: {e}")
            socket_client = None
            return
        while not self.stop_flag.is_set():
            try:
                if time.time() - self.start_time > 600: restart_program()
                data2 = socket_client.recv(9999)
                if not data2: break
                
                if "0f00" in data2.hex()[0:4]:
                    packett = f'08{data2.hex().split("08", 1)[1]}'
                    kk = get_available_room(packett)
                    parsed_data = json.loads(kk)
                    asdj = parsed_data.get("2", {}).get("data", None)
                    tempdata = get_player_status(packett)
                    
                    if asdj == 15:
                        idplayer = None
                        if "5" in parsed_data and "data" in parsed_data["5"]:
                            if "1" in parsed_data["5"]["data"] and "data" in parsed_data["5"]["data"]["1"]:
                                if "1" in parsed_data["5"]["data"]["1"]["data"] and "data" in parsed_data["5"]["data"]["1"]["data"]["1"]:
                                    idplayer = parsed_data["5"]["data"]["1"]["data"]["1"]["data"]
                        
                        if tempdata == "OFFLINE":
                            if idplayer:
                                with api_status_lock:
                                    api_status_responses[str(idplayer)] = {"player_id": str(idplayer), "status": "OFFLINE"}
                        else:
                            if idplayer:
                                idplayer1 = fix_num(idplayer)
                                status_result = {"player_id": str(idplayer), "status": tempdata}
                                if tempdata == "IN ROOM":
                                    idrooom = get_idroom_by_idplayer(packett)
                                    status_result["room_id"] = str(idrooom)
                                if "INSQUAD" in tempdata:
                                    idleader = get_leader(packett)
                                    status_result["leader_id"] = str(idleader)
                                with api_status_lock:
                                    api_status_responses[str(idplayer)] = status_result
                        statusinfo = True
                if data2 == b"": break
            except socket.timeout: continue
            except Exception as e:
                if not self.stop_flag.is_set(): logging.error(f"Error in sockf1 loop: {e}.")
                break
        try:
            if socket_client: socket_client.close()
        except: pass

    def connect(self, tok, host, port, packet, key, iv):
        global clients
        try:
            clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            clients.connect((host, int(port)))
            clients.send(bytes.fromhex(tok))
            
            # sockf1 handles chat/status - using chat_ip from login data if available
            chat_ip = getattr(self, 'chat_ip', host)
            chat_port = getattr(self, 'chat_port', port)
            
            self.sockf1_thread = threading.Thread(target=self.sockf1, args=(tok, chat_ip, chat_port, "anything", key, iv))
            self.sockf1_thread.start()
            clients.settimeout(1.0)
            
            while not self.stop_flag.is_set():
                try:
                    data = clients.recv(9999)
                    if not data: break
                except socket.timeout: continue
                except Exception as e:
                    if not self.stop_flag.is_set(): logging.error(f"Error in connect loop: {e}.")
                    break
        except Exception as e:
            logging.error(f"Error in connect: {e}")
        finally:
            try:
                if clients: clients.close()
            except: pass
    def GET_PAYLOAD_BY_DATA(self, JWT_TOKEN, NEW_ACCESS_TOKEN, date):
        try:
            token_payload_base64 = JWT_TOKEN.split('.')[1]
            token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
            decoded_payload = base64.urlsafe_b64decode(token_payload_base64).decode('utf-8')
            decoded_payload = json.loads(decoded_payload)
            NEW_EXTERNAL_ID = decoded_payload['external_id']
            SIGNATURE_MD5 = decoded_payload['signature_md5']
            
            now = datetime.now()
            now_str = str(now)[:len(str(now)) - 7]
            
            payload = bytes.fromhex("3a07312e3131312e32aa01026172b201203535656437353966636639346638353831336535376232656338343932663563ba010134ea0140366662376664656638363538666430333137346564353531653832623731623231646238313837666130363132633865616631623633616136383766316561659a060134a2060134ca03203734323862323533646566633136343031386336303461316562626665626466")
            payload = payload.replace(b"2024-12-26 13:02:43", now_str.encode())
            payload = payload.replace(b"88332848f415ca9ca98312edcd5fe8bc6547bc6d0477010a7feaf97e3435aa7f", NEW_ACCESS_TOKEN.encode("UTF-8"))
            payload = payload.replace(b"e1ccc10e70d823f950f9f4c337d7d20a", NEW_EXTERNAL_ID.encode("UTF-8"))
            payload = payload.replace(b"7428b253defc164018c604a1ebbfebdf", SIGNATURE_MD5.encode("UTF-8"))
            
            PAYLOAD = payload.hex()
            # Use default_key and default_iv for the initial login payload encryption
            PAYLOAD = encrypt_packet(PAYLOAD, default_key, default_iv)
            PAYLOAD = bytes.fromhex(PAYLOAD)
            ip, port = self.GET_LOGIN_DATA(JWT_TOKEN, PAYLOAD)
            return ip, port
        except Exception as e:
            logging.error(f"Error in GET_PAYLOAD_BY_DATA: {e}")
            return None, None

    def GET_LOGIN_DATA(self, JWT_TOKEN, PAYLOAD):
        url = os.getenv("FF_LOGIN_DATA_URL", "https://clientbp.common.ggbluefox.com/GetLoginData")
        host = os.getenv("FF_LOGIN_DATA_HOST", "clientbp.common.ggbluefox.com")
        headers = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {JWT_TOKEN}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB52',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Host': host,
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate, br',
        }
        max_retries = 3
        attempt = 0
        while attempt < max_retries:
            try:
                response = requests.post(url, headers=headers, data=PAYLOAD, verify=False)
                response.raise_for_status()
                response_content = response.content
                if response.headers.get('Content-Encoding') == 'gzip':
                    try:
                        import gzip
                        response_content = gzip.decompress(response_content)
                    except:
                        pass
                x = response_content.hex()
                json_result = get_available_room(x)
                parsed_data = json.loads(json_result)
                extract_clan_data_from_response(x)
                if '1' in parsed_data:
                    self.player_uid = parsed_data['1']['data']
                if '14' in parsed_data:
                    chat_address = parsed_data['14']['data']
                    chat_parts = chat_address.split(':')
                    self.chat_ip = chat_parts[0]
                    self.chat_port = int(chat_parts[1]) if len(chat_parts) > 1 else 39698
                if '20' in parsed_data:
                    self.clan_id = parsed_data['20']['data']
                if '55' in parsed_data:
                    self.clan_key = parsed_data['55']['data']
                if '32' in parsed_data and 'data' in parsed_data['32']:
                    address = parsed_data['32']['data']
                    ip = address[:len(address) - 6]
                    port = address[len(address) - 5:]
                    return ip, port
                else:
                    logging.error("Missing '32' in parsed_data")
                    attempt += 1; time.sleep(2); continue
            except Exception as e:
                logging.error(f"Error in GET_LOGIN_DATA attempt {attempt+1}: {e}")
                attempt += 1; time.sleep(2)
        return None, None
    def guest_token(self,uid,password):
        url="https://100067.connect.garena.com/oauth/guest/token/grant";headers={"Host":"100067.connect.garena.com","User-Agent":"GarenaMSDK/4.0.19P4(G011A ;Android 10;en;EN;)","Content-Type":"application/x-www-form-urlencoded","Accept-Encoding":"gzip, deflate, br","Connection":"close",};data={"uid":f"{uid}","password":f"{password}","response_type":"token","client_type":"2","client_secret":"2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3","client_id":"100067",};response=requests.post(url,headers=headers,data=data);data=response.json()
        if 'access_token' not in data:
            logging.error(f"Guest token response for UID {uid} missing 'access_token'. Response: {data}")
            if 'error' in data: logging.error(f"Error from Garena: {data.get('error_description', data['error'])}")
            return None
        NEW_ACCESS_TOKEN=data['access_token'];NEW_OPEN_ID=data['open_id'];OLD_ACCESS_TOKEN="6fb7fdef8658fd03174ed551e82b71b21db8187fa0612c8eaf1b63aa687f1eae";OLD_OPEN_ID="55ed759fcf94f85813e57b2ec8492f5c";time.sleep(0.2);data=self.TOKEN_MAKER(OLD_ACCESS_TOKEN,NEW_ACCESS_TOKEN,OLD_OPEN_ID,NEW_OPEN_ID,uid);return(data)
    def decrypt_data(self, encrypted_data, key, iv):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        return unpad(decrypted_data, AES.block_size)

    def emote(self, TarGeT , idT):
        fields = {1: 21, 2: {1: 804266360, 2: 909000001, 5: {1: TarGeT, 3: idT}}}
        packet = create_protobuf_packet(fields).hex()
        header_lenth = len(encrypt_packet(packet, self.key, self.iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        prefix = "0515" + "0" * (6 - len(header_lenth_final))
        final_packet = prefix + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def emotenty(self, uid):
        fields = {1: 4, 2: int(uid), 3: 5, 4: 912038002, 5: 1, 6: int(uid), 7: 1, 8: int(uid), 9: int(uid), 10: int(uid), 11: int(uid)}
        packet = create_protobuf_packet(fields).hex()
        header_lenth = len(encrypt_packet(packet, self.key, self.iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        prefix = "0515" + "0" * (6 - len(header_lenth_final))
        final_packet = prefix + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def send_private_message(self, target_uid, message):
        fields = {1: int(target_uid), 2: str(message), 3: int(datetime.now().timestamp())}
        packet = create_protobuf_packet(fields).hex()
        header_lenth = len(encrypt_packet(packet, self.key, self.iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        prefix = "0515" + "0" * (6 - len(header_lenth_final))
        final_packet = prefix + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def bundle_packet(self, bundle_id):
        fields = {1: 88, 2: {1: {1: bundle_id, 2: 2}, 2: 2}}
        packet = create_protobuf_packet(fields).hex()
        header_lenth = len(encrypt_packet(packet, self.key, self.iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        prefix = "0515" + "0" * (6 - len(header_lenth_final))
        final_packet = prefix + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def ghost_pakcet(self, player_id, nm, secret_code):
        fields = {1: 10, 2: {1: int(player_id), 2: nm, 3: int(secret_code)}}
        packet = create_protobuf_packet(fields).hex()
        header_lenth = len(encrypt_packet(packet, self.key, self.iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        prefix = "0515" + "0" * (6 - len(header_lenth_final))
        final_packet = prefix + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def send_kyro_title(self, owner_uid, chat_code):
        fields = {1: 2, 2: {1: int(owner_uid), 3: "en", 4: str(chat_code)}, 3: "HELLO SIR I AM FALCON BOT"}
        packet = create_protobuf_packet(fields).hex()
        header_lenth = len(encrypt_packet(packet, self.key, self.iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        prefix = "1215" + "0" * (6 - len(header_lenth_final))
        final_packet = prefix + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def go_spectate(self, room_id):
        fields = {1: 20, 2: {1: int(room_id), 2: int(self.player_uid), 3: 2, 4: 0, 5: 0, 6: 1}}
        packet = create_protobuf_packet(fields).hex()
        header_length = len(encrypt_packet(packet, self.key, self.iv)) // 2
        header_hex = dec_to_hex(header_length)
        prefix = "0E15" + "0" * (6 - len(header_hex))
        final_packet = prefix + header_hex + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def AutH_Chat(self, T, uid, code):
        fields = {1: T, 2: {1: uid, 3: "en", 4: str(code)}}
        packet = create_protobuf_packet(fields).hex()
        header_lenth = len(encrypt_packet(packet, self.key, self.iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        prefix = "1215" + "0" * (6 - len(header_lenth_final))
        final_packet = prefix + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def TOKEN_MAKER(self, OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, id):
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB52',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Content-Length': '928',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.ggblueshark.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        data = bytes.fromhex('3a07312e3131312e32aa01026172b201203535656437353966636639346638353831336535376232656338343932663563ba010134ea0140366662376664656638363538666430333137346564353531653832623731623231646238313837666130363132633865616631623633616136383766316561659a060134a2060134ca03203734323862323533646566633136343031386336303461316562626665626466')
        data = data.replace(b'1.111.2', b'1.120.3')
        data = data.replace(OLD_OPEN_ID.encode(), NEW_OPEN_ID.encode())
        data = data.replace(OLD_ACCESS_TOKEN.encode(), NEW_ACCESS_TOKEN.encode())
        hex_data = data.hex()
        d = encrypt_packet(hex_data, default_key, default_iv)
        Final_Payload = bytes.fromhex(d)
        URL = os.getenv("FF_MAJOR_LOGIN_URL", "https://loginbp.ggblueshark.com/MajorLogin")

        RESPONSE = requests.post(URL, headers=headers, data=Final_Payload, verify=False)
        response_data = RESPONSE.content
        if RESPONSE.headers.get('Content-Encoding') == 'gzip':
            try:
                import gzip
                response_data = gzip.decompress(response_data)
            except:
                pass

        try:
            response_data = self.decrypt_data(response_data, default_key, default_iv)
        except Exception as e:
            logging.error(f"Decryption failed: {e}")
            pass

        combined_timestamp, key_ret, iv_ret, BASE64_TOKEN = self.parse_my_message(response_data)
        if RESPONSE.status_code == 200:
            if len(response_data) < 10:
                return False
            ip, port = self.GET_PAYLOAD_BY_DATA(BASE64_TOKEN, NEW_ACCESS_TOKEN, 1)
            self.key = key_ret
            self.iv = iv_ret
            return (BASE64_TOKEN, key_ret, iv_ret, combined_timestamp, ip, port)
        else:
            return False
    def get_tok(self):
        global g_token
        token_data = self.guest_token(self.id, self.password)
        if not token_data:
            logging.critical("Failed to get token data from guest_token. Restarting.")
            restart_program()
        
        token, key, iv, Timestamp, online_ip, online_port = token_data
        g_token = token
        
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            account_id = decoded.get('account_id')
            nickname = decoded.get('nickname')
            region = decoded.get('lock_region')
            client_version = decoded.get('client_version')
            encoded_acc = hex(account_id)[2:]
            hex_value = dec_to_hex(Timestamp)
            time_hex = hex_value
            BASE64_TOKEN_ = token.encode().hex()

            print(f"""
Client Data Retrieved Successfully:

Client ID      : {account_id}
Nickname       : {nickname}
Region         : {region}
Client Version : {client_version}
""")
        except Exception as e:
            logging.error(f"Error processing token: {e}. Restarting.")
            restart_program()
            
        try:
            head = hex(len(encrypt_packet(BASE64_TOKEN_, key, iv)) // 2)[2:]
            length = len(encoded_acc)
            zeros = '00000000'
            if length == 9: zeros = '0000000'
            elif length == 8: zeros = '00000000'
            elif length == 10: zeros = '000000'
            elif length == 7: zeros = '000000000'
            head = f'0115{zeros}{encoded_acc}{time_hex}00000{head}'
            final_token = head + encrypt_packet(BASE64_TOKEN_, key, iv)
        except Exception as e:
            logging.error(f"Error constructing final token: {e}. Restarting.")
            restart_program()
            
        token = final_token
        # Connect to game server (online_ip) and start sockf1 on chat server (self.chat_ip)
        self.connect(token, online_ip, online_port, 'anything', key, iv)
        return token, key, iv
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
        client.start();sleep(0.5);max_wait=30;wait_time=0
        global socket_client
        client_ready=False
        while wait_time<max_wait:
            try:
                if socket_client and not socket_client._closed:
                    try:
                        socket_client.getpeername()
                        if hasattr(client,'key') and client.key is not None:client_ready=True;break
                    except (OSError,AttributeError):pass
            except Exception as e:pass
            if not client.is_alive():
                logging.error("FF_CLIENT thread died during initialization.")
                break
            sleep(0.5);wait_time+=0.5
        if not client_ready:
            if not socket_client or socket_client._closed:return {"error":"Client connection timeout - socket not created or closed. Please try again."}
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
