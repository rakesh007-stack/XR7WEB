# --- COMBINED LEVEL UP + EMOTE BOT (MULTI-USER SESSION SYSTEM) ---
# প্রতিটি user এর জন্য আলাদা bot session

import requests, os, sys, json, time, urllib3, asyncio, signal, secrets, ssl, uuid, threading
from datetime import datetime, timedelta
from aiohttp import web
import aiohttp
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Reference Imports
from Pb2 import DEcwHisPErMsG_pb2, MajoRLoGinrEs_pb2, PorTs_pb2, MajoRLoGinrEq_pb2, sQ_pb2, Team_msg_pb2
from xC4 import *
from xHeaders import *

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIG & HEADERS ---
Hr = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/x-www-form-urlencoded",
    'Expect': "100-continue",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': "v1 1",
    'ReleaseVersion': "OB52"
}

# --- EMOTES DATA ---
EMOTES_DATA = []
try:
    with open('emotes.json', 'r', encoding='utf-8') as f:
        EMOTES_DATA = json.load(f)
except:
    print("[WARNING] emotes.json not found!")

# --- MULTI-USER SESSION STORAGE ---
# session_id -> UserBot instance
USER_SESSIONS = {}
SESSION_LOCK = threading.Lock()
LOOP = None

# Session cleanup - remove inactive sessions after 30 minutes
SESSION_TIMEOUT = 30 * 60  # 30 minutes

def cleanup_old_sessions():
    """Remove sessions that have been inactive for too long"""
    current_time = time.time()
    with SESSION_LOCK:
        expired = [sid for sid, bot in USER_SESSIONS.items() 
                   if current_time - bot.last_activity > SESSION_TIMEOUT]
        for sid in expired:
            print(f"[Session] Cleaning up expired session: {sid[:8]}...")
            asyncio.create_task(USER_SESSIONS[sid].disconnect())
            del USER_SESSIONS[sid]

# --- PACKET GENERATORS ---
async def encrypt_packet(packet_hex, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(bytes.fromhex(packet_hex), AES.block_size)).hex()

async def encrypted_proto(encoded_hex):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(encoded_hex, AES.block_size))

async def start_auto_packet(key, iv, region):
    fields = {1: 9, 2: {1: 12480598706}}
    pt = '0514' if region.lower() == 'ind' else ('0519' if region.lower()=='bd' else '0515')
    return await GeneRaTePk((await CrEaTe_ProTo(fields)).hex(), pt, key, iv)

async def leave_squad_packet(key, iv, region):
    fields = {1: 7, 2: {1: 12480598706}}
    pt = '0514' if region.lower() == 'ind' else ('0519' if region.lower()=='bd' else '0515')
    return await GeneRaTePk((await CrEaTe_ProTo(fields)).hex(), pt, key, iv)

async def join_teamcode_packet(tc, key, iv, region):
    fields = {1: 4, 2: {4: bytes.fromhex("01090a0b121920"), 5: str(tc), 6: 6, 8: 1, 9: {2: 800, 6: 11, 8: "1.120.1", 9: 5, 10: 1}}}
    pt = '0514' if region.lower() == 'ind' else ('0519' if region.lower()=='bd' else '0515')
    return await GeneRaTePk((await CrEaTe_ProTo(fields)).hex(), pt, key, iv)

# Emote packet
async def emote_packet(target_uid, emote_id, key, iv, region):
    fields = {
        1: 21,
        2: {
            1: 804266360,
            2: 909000001,
            5: {
                1: int(target_uid),
                3: int(emote_id),
            }
        }
    }
    pt = '0514' if region.lower() == 'ind' else ('0519' if region.lower()=='bd' else '0515')
    return await GeneRaTePk((await CrEaTe_ProTo(fields)).hex(), pt, key, iv)

# --- 5-PLAYER GROUP INVITE PACKETS ---
async def open_squad_packet(key, iv, region):
    """Open a squad/party on Social Island"""
    fields = {1: 1, 2: {2: "\u0001", 3: 1, 4: 1, 5: "en", 9: 1, 11: 1, 13: 1, 14: {2: 5756, 6: 11, 8: "1.120.1", 9: 2, 10: 4}}}
    pt = '0514' if region.lower() == 'ind' else ('0519' if region.lower()=='bd' else '0515')
    return await GeneRaTePk((await CrEaTe_ProTo(fields)).hex(), pt, key, iv)

async def change_squad_size_packet(size, bot_uid, key, iv, region):
    """Change squad size to 5 players"""
    fields = {1: 17, 2: {1: int(bot_uid), 2: 1, 3: int(size - 1), 4: 62, 5: "\u001a", 8: 5, 13: 329}}
    pt = '0514' if region.lower() == 'ind' else ('0519' if region.lower()=='bd' else '0515')
    return await GeneRaTePk((await CrEaTe_ProTo(fields)).hex(), pt, key, iv)

async def send_invite_packet(player_uid, key, iv, region):
    """Send invite to a player"""
    fields = {1: 2, 2: {1: int(player_uid), 2: region, 4: 1}}
    pt = '0514' if region.lower() == 'ind' else ('0519' if region.lower()=='bd' else '0515')
    return await GeneRaTePk((await CrEaTe_ProTo(fields)).hex(), pt, key, iv)

# --- AUTH FUNCTIONS ---
async def GeNeRaTeAccEss(uid, password, bot=None):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": (await Ua()),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, data=data) as r:
                if r.status != 200: 
                    if bot: bot.log(f"Access Token Failed: {r.status}")
                    return (None, None)
                d = await r.json()
                return (d.get("open_id"), d.get("access_token"))
    except Exception as e:
        if bot: bot.log(f"Access Token Error: {e}")
        return (None, None)

async def EncRypTMajoRLoGin(open_id, access_token):
    p = MajoRLoGinrEq_pb2.MajorLogin()
    p.event_time = str(datetime.now())[:-7]
    p.game_name = "free fire"; p.platform_id = 1; p.client_version = "1.120.1"
    p.open_id = open_id; p.access_token = access_token
    p.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    p.system_hardware = "Handheld"; p.telecom_operator = "Verizon"; p.network_type = "WIFI"
    p.screen_width = 1920; p.screen_height = 1080; p.screen_dpi = "280"
    p.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    p.memory = 3003; p.gpu_renderer = "Adreno (TM) 640"; p.gpu_version = "OpenGL ES 3.1 v1.46"
    p.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"; p.client_ip = "223.191.51.89"
    p.language = "en"; p.open_id_type = "4"; p.device_type = "Handheld"
    p.memory_available.version = 55; p.memory_available.hidden_value = 81
    p.platform_sdk_id = 1; p.network_operator_a = "Verizon"; p.network_type_a = "WIFI"
    p.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    p.external_storage_total = 36235; p.external_storage_available = 31335
    p.internal_storage_total = 2519; p.internal_storage_available = 703
    p.game_disk_storage_available = 25010; p.game_disk_storage_total = 26628
    p.external_sdcard_avail_storage = 32992; p.external_sdcard_total_storage = 36235
    p.login_by = 3; p.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    p.reg_avatar = 1; p.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    p.channel_type = 3; p.cpu_type = 2; p.cpu_architecture = "64"
    p.client_version_code = "2019118695"; p.graphics_api = "OpenGLES2"
    p.supported_astc_bitset = 16383; p.login_open_id_type = 4
    p.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWA0FUgsvA1snWlBaO1kFYg=="
    p.loading_time = 13564; p.release_channel = "android"
    p.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    p.android_engine_init_flag = 110009; p.if_push = 1; p.is_vpn = 1
    p.origin_platform_type = "4"; p.primary_platform_type = "4"
    return await encrypted_proto(p.SerializeToString())

async def MajorLogin(payload, bot=None):
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=payload, headers=Hr, ssl=ssl_context) as r:
                if r.status == 200: return await r.read()
                if bot: bot.log(f"MajorLogin Failed: Status {r.status}")
    except Exception as e: 
        if bot: bot.log(f"MajorLogin Error: {e}")
    return None

async def DecRypTMajoRLoGin(data):
    p = MajoRLoGinrEs_pb2.MajorLoginRes(); p.ParseFromString(data); return p

async def GetLoginData(url, payload, token):
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    h = Hr.copy(); h['Authorization'] = f"Bearer {token}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(f"{url}/GetLoginData", data=payload, headers=h, ssl=ssl_context) as r:
                return await r.read() if r.status == 200 else None
    except: return None

async def DecRypTLoGinDaTa(data):
    p = PorTs_pb2.GetLoginData(); p.ParseFromString(data); return p

async def xAuThSTarTuP(uid, token, ts, key, iv):
    uid_hex = hex(uid)[2:]
    enc_ts = await DecodE_HeX(ts)
    enc_tok = (token.encode()).hex()
    pkt = await EnC_PacKeT(enc_tok, key, iv)
    plen = hex(len(pkt)//2)[2:]
    headers = '0'*(16-len(uid_hex))
    if len(uid_hex)==9: headers = '0000000'
    elif len(uid_hex)==10: headers='000000'
    elif len(uid_hex)==8: headers='00000000'
    return f"0115{headers}{uid_hex}{enc_ts}00000{plen}{pkt}"

async def SEndPacKeT(w, packet):
    try:
        if w: w.write(packet); await w.drain()
    except: pass

# --- USER BOT CLASS (Each user gets their own instance) ---
class UserBot:
    def __init__(self, session_id):
        self.session_id = session_id
        self.status = "OFFLINE"
        self.log_msg = "Ready to connect."
        self.stop_farming = False
        self.last_activity = time.time()
        
        # State
        self.uid = None
        self.password = None
        self.account_name = None
        self.region = None
        self.key = None
        self.iv = None
        self.tasks = {'login': None, 'farming': None, 'tcp_online': None, 'tcp_chat': None}
        self.writers = {'online': None, 'whisper': None}
        
        # Emote state
        self.current_team_code = None
        self.is_in_squad = False

    def log(self, msg):
        self.log_msg = msg
        self.last_activity = time.time()
        print(f"[{self.session_id[:8]}] {msg}")

    async def connect(self, game_uid, game_pass):
        self.uid = game_uid
        self.password = game_pass
        self.status = "LOGGING_IN"
        self.log(f"Connecting to Game UID: {game_uid}")
        
        try:
            oid, acc = await GeNeRaTeAccEss(game_uid, game_pass, self)
            if not oid: 
                self.log("Invalid UID/Pass")
                self.status = "OFFLINE"
                return
            
            pyl = await EncRypTMajoRLoGin(oid, acc)
            res = await MajorLogin(pyl, self)
            if not res: 
                self.log("MajorLogin Failed. Check Logs.")
                self.status = "OFFLINE"
                return
            
            auth = await DecRypTMajoRLoGin(res)
            self.region = auth.region
            self.key = auth.key
            self.iv = auth.iv
            
            ld = await GetLoginData(auth.url, pyl, auth.token)
            if not ld: 
                self.log("GetLoginData Failed")
                self.status = "OFFLINE"
                return
            
            data = await DecRypTLoGinDaTa(ld)
            self.account_name = data.AccountName
            
            ip_on, port_on = data.Online_IP_Port.split(":")
            ip_chat, port_chat = data.AccountIP_Port.split(":")
            
            auth_token = await xAuThSTarTuP(int(auth.account_uid), auth.token, int(auth.timestamp), self.key, self.iv)
            
            # Start TCP
            self.tasks['tcp_online'] = asyncio.create_task(self.tcp_connect(ip_on, port_on, auth_token, 'online'))
            self.tasks['tcp_chat'] = asyncio.create_task(self.tcp_connect(ip_chat, port_chat, auth_token, 'whisper'))
            
            self.status = "ONLINE"
            self.log(f"Connected as {self.account_name}")
            
        except Exception as e:
            self.log(f"Login Error: {e}")
            self.status = "OFFLINE"

    async def tcp_connect(self, ip, port, token, w_type):
        try:
            r, w = await asyncio.open_connection(ip, int(port))
            self.writers[w_type] = w
            w.write(bytes.fromhex(token))
            await w.drain()
            while True:
                d = await r.read(9999)
                if not d: break
        except Exception as e:
            print(f"[{self.session_id[:8]}] TCP Error ({w_type}): {e}")
        self.writers[w_type] = None

    # --- LEVEL UP FARMING ---
    async def start_farming(self, team_code):
        if self.status not in ['ONLINE', 'FARMING']: return
        self.stop_farming = False
        self.status = "FARMING"
        self.log(f"Farming started: {team_code}")
        
        while not self.stop_farming:
            try:
                # JOIN
                jp = await join_teamcode_packet(team_code, self.key, self.iv, self.region)
                await SEndPacKeT(self.writers['online'], jp)
                await asyncio.sleep(2)
                
                # SPAM START
                sp = await start_auto_packet(self.key, self.iv, self.region)
                end = time.time() + 18
                while time.time() < end and not self.stop_farming:
                    await SEndPacKeT(self.writers['online'], sp)
                    await asyncio.sleep(0.2)
                if self.stop_farming: break
                
                # WAIT
                await asyncio.sleep(20)
                if self.stop_farming: break
                
                # LEAVE
                lp = await leave_squad_packet(self.key, self.iv, self.region)
                await SEndPacKeT(self.writers['online'], lp)
                await asyncio.sleep(2)
                
            except Exception as e: 
                self.log(f"Farm Err: {e}")
                await asyncio.sleep(1)
        
        self.status = "ONLINE"
        self.log("Farming Stopped")

    # --- EMOTE SENDING ---
    async def send_emote(self, team_code, uids_list, emote_id):
        if self.status not in ['ONLINE', 'FARMING']:
            return {"status": "error", "message": "Bot not connected"}
        
        self.last_activity = time.time()
        
        try:
            # Join squad if not already in or different team
            if not self.is_in_squad or self.current_team_code != team_code:
                self.log(f"Joining team: {team_code}")
                jp = await join_teamcode_packet(team_code, self.key, self.iv, self.region)
                await SEndPacKeT(self.writers['online'], jp)
                await asyncio.sleep(0.3)
                self.is_in_squad = True
                self.current_team_code = team_code
            
            # Send emote to each UID
            for uid in uids_list:
                self.log(f"Sending emote {emote_id} to UID: {uid}")
                ep = await emote_packet(uid, emote_id, self.key, self.iv, self.region)
                await SEndPacKeT(self.writers['online'], ep)
                await asyncio.sleep(0.1)
            
            self.log(f"Emote sent successfully!")
            return {"status": "success", "message": f"Emote {emote_id} sent to {len(uids_list)} UIDs!"}
            
        except Exception as e:
            self.log(f"Emote Error: {e}")
            return {"status": "error", "message": str(e)}

    async def leave_squad(self):
        if self.is_in_squad:
            lp = await leave_squad_packet(self.key, self.iv, self.region)
            await SEndPacKeT(self.writers['online'], lp)
            self.is_in_squad = False
            self.current_team_code = None
            self.log("Left squad")

    # --- 5-PLAYER GROUP INVITE ---
    async def create_group_invite(self, uids_list):
        """Create 5-player group on Social Island and invite players"""
        if self.status not in ['ONLINE', 'FARMING']:
            return {"status": "error", "message": "Bot not connected"}
        
        self.last_activity = time.time()
        
        try:
            # Step 1: Open Squad on Social Island
            self.log("Opening 5-player squad on Social Island...")
            open_pkt = await open_squad_packet(self.key, self.iv, self.region)
            await SEndPacKeT(self.writers['online'], open_pkt)
            await asyncio.sleep(0.5)
            
            # Step 2: Change squad size to 5
            self.log("Setting squad size to 5 players...")
            size_pkt = await change_squad_size_packet(5, self.uid, self.key, self.iv, self.region)
            await SEndPacKeT(self.writers['online'], size_pkt)
            await asyncio.sleep(0.3)
            
            # Step 3: Send invite to each UID
            invited_count = 0
            for uid in uids_list:
                if uid:
                    self.log(f"Inviting player: {uid}")
                    inv_pkt = await send_invite_packet(uid, self.key, self.iv, self.region)
                    await SEndPacKeT(self.writers['online'], inv_pkt)
                    invited_count += 1
                    await asyncio.sleep(0.2)
            
            self.log(f"Group created! {invited_count} players invited. Waiting 3 sec then leaving...")
            
            # Step 4: Wait 3 seconds then leave the group
            await asyncio.sleep(3)
            
            # Leave squad
            self.log("Leaving group after 3 seconds...")
            lp = await leave_squad_packet(self.key, self.iv, self.region)
            await SEndPacKeT(self.writers['online'], lp)
            self.log("Left group successfully!")
            
            return {"status": "success", "message": f"5-Player group created! {invited_count} players invited. Bot left after 3 seconds."}
            
        except Exception as e:
            self.log(f"Group Invite Error: {e}")
            return {"status": "error", "message": str(e)}

    async def disconnect(self):
        self.stop_farming = True
        for t in self.tasks.values():
            if t and not t.done(): t.cancel()
        self.status = "OFFLINE"
        self.is_in_squad = False
        self.current_team_code = None
        self.log("Disconnected")

# --- HELPER: Get or create user session ---
def get_session_id(request):
    """Get session ID from cookie, or create new one"""
    session_id = request.cookies.get('session_id')
    return session_id

def get_user_bot(request):
    """Get the bot instance for this user's session"""
    session_id = get_session_id(request)
    if not session_id:
        return None, None
    
    with SESSION_LOCK:
        if session_id in USER_SESSIONS:
            bot = USER_SESSIONS[session_id]
            bot.last_activity = time.time()
            return bot, session_id
    return None, session_id

# --- WEB ROUTES ---
async def w_create_session(r):
    """Create a new session for a user"""
    session_id = str(uuid.uuid4())
    
    with SESSION_LOCK:
        USER_SESSIONS[session_id] = UserBot(session_id)
    
    print(f"[Session] New session created: {session_id[:8]}...")
    
    response = web.json_response({'success': True, 'session_id': session_id})
    response.set_cookie('session_id', session_id, max_age=86400, httponly=True, samesite='Lax')
    return response

async def w_status(r):
    bot, session_id = get_user_bot(r)
    
    if not bot:
        return web.json_response({
            'status': 'NO_SESSION',
            'log': 'Please refresh the page to start a new session.',
            'account_name': None
        })
    
    return web.json_response({
        'status': bot.status, 
        'log': bot.log_msg,
        'account_name': bot.account_name,
        'session_id': session_id[:8] if session_id else None
    })

async def w_connect(r):
    bot, session_id = get_user_bot(r)
    
    if not bot:
        return web.json_response({'error': 'No session. Please refresh.'}, status=400)
    
    d = await r.json()
    asyncio.create_task(bot.connect(d.get('uid'), d.get('password')))
    return web.json_response({'success': True})

async def w_disconnect(r):
    bot, session_id = get_user_bot(r)
    
    if bot:
        await bot.disconnect()
    return web.json_response({'success': True})

async def w_farm_start(r):
    bot, session_id = get_user_bot(r)
    
    if not bot:
        return web.json_response({'error': 'No session'}, status=400)
    
    d = await r.json()
    if bot.tasks['farming']: bot.tasks['farming'].cancel()
    bot.tasks['farming'] = asyncio.create_task(bot.start_farming(d.get('team_code')))
    return web.json_response({'success': True})

async def w_farm_stop(r):
    bot, session_id = get_user_bot(r)
    
    if bot:
        bot.stop_farming = True
    return web.json_response({'success': True})

# --- EMOTE API ---
async def w_send_emote(r):
    bot, session_id = get_user_bot(r)
    
    if not bot or bot.status not in ['ONLINE', 'FARMING']:
        return web.json_response({'status': 'error', 'message': 'Bot not connected'}, status=400)
    
    try:
        d = await r.json()
        team_code = d.get('team_code')
        emote_id = d.get('emote_id')
        uids = d.get('uids', [])
        
        if not team_code or not emote_id or not uids:
            return web.json_response({'status': 'error', 'message': 'Missing team_code, emote_id, or uids'}, status=400)
        
        uids_int = [int(u) for u in uids]
        result = await bot.send_emote(team_code, uids_int, int(emote_id))
        return web.json_response(result)
        
    except Exception as e:
        return web.json_response({'status': 'error', 'message': str(e)}, status=500)

async def w_emotes_list(r):
    return web.json_response(EMOTES_DATA)

async def w_leave_squad(r):
    bot, session_id = get_user_bot(r)
    
    if bot:
        await bot.leave_squad()
    return web.json_response({'success': True})

# --- 5-PLAYER GROUP INVITE API ---
async def w_group_invite(r):
    bot, session_id = get_user_bot(r)
    
    if not bot or bot.status not in ['ONLINE', 'FARMING']:
        return web.json_response({'status': 'error', 'message': 'Bot not connected'}, status=400)
    
    try:
        d = await r.json()
        uids = d.get('uids', [])
        
        if not uids or len(uids) == 0:
            return web.json_response({'status': 'error', 'message': 'কমপক্ষে ১টা UID দিন'}, status=400)
        
        # Convert to integers
        uids_int = [int(u) for u in uids if u]
        
        result = await bot.create_group_invite(uids_int)
        return web.json_response(result)
        
    except Exception as e:
        return web.json_response({'status': 'error', 'message': str(e)}, status=500)

async def w_session_info(r):
    """Get info about active sessions (for debugging)"""
    with SESSION_LOCK:
        sessions = []
        for sid, bot in USER_SESSIONS.items():
            sessions.append({
                'session_id': sid[:8],
                'status': bot.status,
                'account': bot.account_name,
                'inactive_seconds': int(time.time() - bot.last_activity)
            })
    return web.json_response({
        'total_sessions': len(sessions),
        'sessions': sessions
    })

# --- PAGES ---
async def index(r): 
    return web.FileResponse('dashboard.html')

async def init_app():
    app = web.Application()
    app.router.add_get('/', index)
    
    # Session Management
    app.router.add_post('/api/create_session', w_create_session)
    app.router.add_get('/api/session_info', w_session_info)
    
    # Status & Connection
    app.router.add_get('/api/status', w_status)
    app.router.add_post('/api/connect', w_connect)
    app.router.add_post('/api/disconnect', w_disconnect)
    
    # Level Up Farming
    app.router.add_post('/api/farm_start', w_farm_start)
    app.router.add_post('/api/farm_stop', w_farm_stop)
    
    # Emote API
    app.router.add_post('/api/send_emote', w_send_emote)
    app.router.add_get('/api/emotes', w_emotes_list)
    app.router.add_post('/api/leave_squad', w_leave_squad)
    app.router.add_post('/api/group_invite', w_group_invite)
    
    # Static files (emote images, CSS)
    app.router.add_static('/static/', path='static', name='static')
    
    return app

# Periodic cleanup task
async def cleanup_task():
    while True:
        await asyncio.sleep(300)  # Every 5 minutes
        cleanup_old_sessions()

if __name__ == '__main__':
    async def main():
        global LOOP
        LOOP = asyncio.get_event_loop()
        
        # Start cleanup task
        asyncio.create_task(cleanup_task())
        
        app = await init_app()
        print("=" * 60)
        print("  COMBINED LEVEL UP + EMOTE BOT (MULTI-USER)")
        print("  প্রতিটি user এর জন্য আলাদা session/bot")
        print("  Started on http://0.0.0.0:30443")
        print("=" * 60)
        runner = web.AppRunner(app)
        await runner.setup()
        # Try to get port from SERVER_PORT (Pterodactyl) or PORT, default to 30443
        port = int(os.environ.get('SERVER_PORT', os.environ.get('PORT', 30443)))
        site = web.TCPSite(runner, '0.0.0.0', port)
        await site.start()
        print(f"Server running at http://0.0.0.0:{port}")
        print("Each user will get their own separate bot session!")
        while True:
            await asyncio.sleep(3600)
    
    asyncio.run(main())