import asyncio
import websockets
import json
import logging
from datetime import datetime

# Scapy for packet manipulation
from scapy.all import sniff, TCP, UDP, DNS, ARP, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, Dot11Elt, IP, IPv6, Raw, get_if_list, Dot11EltDSSSet, Dot11Deauth, Dot11Disas
from scapy.config import conf

# Multiprocessing for non-blocking sniffing
from multiprocessing import Process, Queue
import queue

# System and external service utilities
import psutil

# --- PostgreSQL Imports ---
import psycopg2
import psycopg2.extras
import os
from dotenv import load_dotenv

load_dotenv()

# --- Configuration ---
HOST = '0.0.0.0'
PORT = 8765
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S,%f'[:-3])
logger = logging.getLogger(__name__)

# --- PostgreSQL Connection Details ---
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")

# --- Global State ---
clients = set()
sniffer_process = None
packet_feed_queue = Queue()
current_session_id = None
arp_cache = {}
alert_thresholds = {"cpu": 90, "throughput": 100, "arpSpoofing": True, "deauthAttack": True}
live_bytes_per_second = 0

# --- Database Functions ---
def get_db_connection():
    try:
        conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST, port=DB_PORT)
        return conn
    except psycopg2.OperationalError as e:
        logger.critical(f"FATAL: Could not connect to PostgreSQL database: {e}")
        raise

def init_db():
    sql_create_sessions = "CREATE TABLE IF NOT EXISTS sessions (id BIGSERIAL PRIMARY KEY, start_time TIMESTAMPTZ NOT NULL DEFAULT NOW(), end_time TIMESTAMPTZ NULL);"
    sql_alter_sessions = "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS end_time TIMESTAMPTZ NULL;"
    sql_create_packets = "CREATE TABLE IF NOT EXISTS packets (id BIGSERIAL PRIMARY KEY, session_id BIGINT NOT NULL, timestamp DOUBLE PRECISION NOT NULL, packet_data JSONB NOT NULL, CONSTRAINT fk_session FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE);"
    try:
        with get_db_connection() as con:
            with con.cursor() as cur:
                cur.execute(sql_create_sessions); cur.execute(sql_alter_sessions); cur.execute(sql_create_packets)
        logger.info("Database schema verified/created successfully.")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")

def finish_all_open_sessions():
    sql = "UPDATE sessions SET end_time = NOW() WHERE end_time IS NULL;"
    try:
        with get_db_connection() as con:
            with con.cursor() as cur:
                cur.execute(sql)
                if cur.rowcount > 0: logger.info(f"Cleaned up {cur.rowcount} unfinished session(s) from previous runs.")
    except Exception as e:
        logger.error(f"Error cleaning up old sessions: {e}")

# --- NEW: Powerful Global Analysis Function ---
def get_global_analysis_data():
    results = {
        "summary": {"total_packets": 0, "total_data_gb": 0, "total_sessions": 0},
        "activity_by_day": [],
        "top_talkers": [],
        "protocol_dist": []
    }
    try:
        with get_db_connection() as con:
            with con.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                # Summary Stats
                cur.execute("SELECT COUNT(*) as packet_count, SUM((packet_data->'summary'->>'length')::bigint) as total_bytes FROM packets;")
                summary_data = cur.fetchone()
                results["summary"]["total_packets"] = summary_data["packet_count"] or 0
                results["summary"]["total_data_gb"] = round(float(summary_data["total_bytes"] or 0) / 1073741824, 2)
                cur.execute("SELECT COUNT(*) as session_count FROM sessions;")
                results["summary"]["total_sessions"] = cur.fetchone()["session_count"] or 0

                # Activity by Day
                cur.execute("""
                    SELECT DATE_TRUNC('day', TO_TIMESTAMP(timestamp))::DATE as day, COUNT(*) as packet_count
                    FROM packets GROUP BY day ORDER BY day;
                """)
                results["activity_by_day"] = [dict(row) for row in cur.fetchall()]

                # Top Talkers
                cur.execute("""
                    SELECT packet_data->'summary'->>'source' as talker, COUNT(*) as packet_count
                    FROM packets GROUP BY talker ORDER BY packet_count DESC LIMIT 10;
                """)
                results["top_talkers"] = [dict(row) for row in cur.fetchall()]

                # Protocol Distribution
                cur.execute("""
                    SELECT packet_data->'summary'->>'protocol' as protocol, COUNT(*) as packet_count
                    FROM packets GROUP BY protocol ORDER BY packet_count DESC LIMIT 8;
                """)
                results["protocol_dist"] = [dict(row) for row in cur.fetchall()]
        return results
    except Exception as e:
        logger.error(f"Error getting global analysis data: {e}")
        return results

def create_session():
    sql = "INSERT INTO sessions (start_time) VALUES (NOW()) RETURNING id;"
    try:
        with get_db_connection() as con:
            with con.cursor() as cur: cur.execute(sql); return cur.fetchone()[0]
    except Exception as e: logger.error(f"Error creating session: {e}"); return None
def end_session_in_db(session_id):
    sql = "UPDATE sessions SET end_time = NOW() WHERE id = %s;"
    try:
        with get_db_connection() as con:
            with con.cursor() as cur: cur.execute(sql, (session_id,))
        logger.info(f"Ended session {session_id} in database.")
    except Exception as e: logger.error(f"Error ending session {session_id}: {e}")
def get_sessions():
    sql = """SELECT id, TO_CHAR(start_time, 'YYYY-MM-DD HH24:MI:SS') as start_time, CASE WHEN end_time IS NULL THEN 'In Progress' ELSE 'Finished' END as status, CASE WHEN end_time IS NOT NULL THEN TO_CHAR(end_time - start_time, 'HH24:MI:SS') ELSE TO_CHAR(NOW() - start_time, 'HH24:MI:SS') END as duration FROM sessions ORDER BY start_time DESC;"""
    try:
        with get_db_connection() as con:
            with con.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur: cur.execute(sql); return [dict(row) for row in cur.fetchall()]
    except Exception as e: logger.error(f"Error getting sessions: {e}"); return []
def get_packets_for_session(session_id):
    sql = "SELECT packet_data FROM packets WHERE session_id = %s ORDER BY timestamp ASC;"
    try:
        with get_db_connection() as con:
            with con.cursor() as cur: cur.execute(sql, (session_id,)); return [row[0] for row in cur.fetchall()]
    except Exception as e: logger.error(f"Error getting packets for session {session_id}: {e}"); return []
def delete_session(session_id):
    sql = "DELETE FROM sessions WHERE id = %s;"
    try:
        with get_db_connection() as con:
            with con.cursor() as cur: cur.execute(sql, (session_id,)); logger.info(f"Deleted session {session_id}")
    except Exception as e: logger.error(f"Error deleting session {session_id}: {e}")

# ... (Packet processing functions are unchanged) ...
def hexdump(data, length=16):
    lines = [];
    for i in range(0, len(data), length):
        chunk = data[i:i + length]; hex_part = ' '.join(f"{b:02x}" for b in chunk); ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        lines.append(f"{i:04x}  {hex_part:<{length * 3}}  {ascii_part}")
    return '\n'.join(lines)
def generate_clean_summary(packet):
    if packet.haslayer(Dot11):
        if packet.type == 0:
            if packet.subtype == 8: ssid = packet.getlayer(Dot11Elt, ID=0).info.decode(errors='ignore') if packet.haslayer(Dot11Elt) else 'Hidden'; return f"Beacon Frame (SSID: {ssid})"
            if packet.subtype == 4: ssid = packet.getlayer(Dot11Elt, ID=0).info.decode(errors='ignore') if packet.haslayer(Dot11Elt) and packet[Dot11Elt].info else 'Broadcast'; return f"Probe Request for '{ssid}'"
            if packet.subtype == 5: ssid = packet.getlayer(Dot11Elt, ID=0).info.decode(errors='ignore') if packet.haslayer(Dot11Elt) else 'Hidden'; return f"Probe Response (SSID: {ssid})"
            if packet.subtype == 12: return "Deauthentication Frame"
            if packet.subtype == 10: return "Disassociation Frame"
        elif packet.type == 1:
            if packet.subtype == 11: return "Control: RTS";
            if packet.subtype == 12: return "Control: CTS";
            if packet.subtype == 13: return "Control: ACK"
        elif packet.type == 2: return "Data Frame"
    if packet.haslayer(ARP): return f"ARP {packet[ARP].op_name} for {packet[ARP].pdst} from {packet[ARP].psrc}"
    if packet.haslayer(IP):
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
        if packet.haslayer(TCP): return f"TCP {src_ip}:{packet[TCP].sport} -> {dst_ip}:{packet[TCP].dport}"
        if packet.haslayer(UDP): return f"UDP {src_ip}:{packet[UDP].sport} -> {dst_ip}:{packet[UDP].dport}"
    return packet.summary()
def extract_packet_fields_scapy(packet):
    try:
        final_data = {}
        security_event = None
        if alert_thresholds["deauthAttack"] and (packet.haslayer(Dot11Deauth) or packet.haslayer(Dot11Disas)):
            event_type = "Deauth" if packet.haslayer(Dot11Deauth) else "Disas"
            security_event = {"time": float(packet.time), "type": "Wi-Fi Attack", "message": f"{event_type} frame: {packet.addr2} -> {packet.addr1}"}
        elif alert_thresholds["arpSpoofing"] and packet.haslayer(ARP) and packet.op == 2:
            ip, mac = packet.psrc, packet.hwsrc
            if ip in arp_cache and arp_cache[ip] != mac:
                security_event = {"time": float(packet.time), "type": "ARP Spoofing?", "message": f"IP {ip} is now at {mac} (was {arp_cache[ip]})"}
            arp_cache[ip] = mac
        if security_event: final_data["security_event"] = security_event
        wireless_meta = None
        if packet.haslayer(Dot11):
            source_mac = packet.addr2
            if packet.haslayer(Dot11Beacon):
                ssid_layer = packet.getlayer(Dot11Elt, ID=0); ssid = ssid_layer.info.decode(errors='ignore') if ssid_layer and hasattr(ssid_layer, 'info') else 'Hidden SSID'; channel = 'N/A'; dss_layer = packet.getlayer(Dot11EltDSSSet);
                if dss_layer: channel = dss_layer.channel
                if source_mac: wireless_meta = {"type": "beacon", "bssid": source_mac, "ssid": ssid, "channel": channel}
            elif packet.haslayer(Dot11ProbeReq):
                ssid_layer = packet.getlayer(Dot11Elt, ID=0); probed_ssid = ssid_layer.info.decode(errors='ignore') if ssid_layer and hasattr(ssid_layer, 'info') and ssid_layer.info else 'Broadcast'
                if source_mac: wireless_meta = {"type": "probe_req", "client_mac": source_mac, "probed_ssid": probed_ssid}
        summary = {"time": float(packet.time), "source": "N/A", "destination": "N/A", "protocol": "Unknown", "length": len(packet), "info": generate_clean_summary(packet), "dport": None}
        if packet.haslayer(IP):
            summary["source"], summary["destination"], summary["protocol"] = packet[IP].src, packet[IP].dst, packet.lastlayer().name
            if packet.haslayer(TCP): summary["dport"] = packet[TCP].dport
            if packet.haslayer(UDP): summary["dport"] = packet[UDP].dport
        elif packet.haslayer(Dot11):
            if packet.addr2: summary["source"] = packet.addr2
            if packet.addr1: summary["destination"] = packet.addr1
            summary["protocol"] = "WLAN"
        elif packet.haslayer(ARP): summary["source"], summary["destination"], summary["protocol"] = packet[ARP].psrc, packet[ARP].pdst, "ARP"
        full_packet_dict = {}
        counter = 0; layer = packet
        while layer:
            if layer.name == "Raw": break
            layer_name = f"{counter}:{layer.name.lower().replace(' ', '_')}"; fields = {f: str(v) for f, v in layer.fields.items()}; full_packet_dict[layer_name] = fields
            counter += 1; layer = layer.payload
        if packet.haslayer(Raw): full_packet_dict["raw_payload"] = hexdump(packet.getlayer(Raw).load)
        final_data.update({"summary": summary, "full_packet": full_packet_dict})
        if wireless_meta: final_data["wireless_meta"] = wireless_meta
        return final_data
    except Exception: return None
def sniffing_process_target(interface, bpf_filter, q, session_id):
    logger.info(f"Sniffer process started on '{interface}' for session {session_id}...")
    def packet_handler(packet):
        packet_data = extract_packet_fields_scapy(packet)
        if packet_data: q.put((session_id, packet_data))
    try: sniff(iface=interface, prn=packet_handler, store=False, filter=bpf_filter)
    except Exception as e: logger.critical(f"Critical error in sniffer process: {e}")
    finally: logger.info("Sniffer process terminated.")
async def db_writer_loop(q, batch_size=100, flush_interval=2.0):
    packet_batch = []; last_flush_time = asyncio.get_running_loop().time(); con = get_db_connection()
    while True:
        try:
            session_id, packet_data = await asyncio.wait_for(asyncio.get_running_loop().run_in_executor(None, q.get), timeout=flush_interval)
            packet_batch.append((session_id, packet_data.get('summary', {}).get('time'), json.dumps(packet_data)))
            current_time = asyncio.get_running_loop().time()
            if len(packet_batch) >= batch_size or (current_time - last_flush_time) >= flush_interval:
                if packet_batch:
                    with con.cursor() as cur: sql_insert = "INSERT INTO packets (session_id, timestamp, packet_data) VALUES %s"; psycopg2.extras.execute_values(cur, sql_insert, packet_batch); con.commit()
                    packet_batch.clear()
                last_flush_time = current_time
        except asyncio.TimeoutError:
            if packet_batch:
                with con.cursor() as cur: sql_insert = "INSERT INTO packets (session_id, timestamp, packet_data) VALUES %s"; psycopg2.extras.execute_values(cur, sql_insert, packet_batch); con.commit()
                packet_batch.clear()
            last_flush_time = asyncio.get_running_loop().time()
        except (psycopg2.InterfaceError, psycopg2.OperationalError) as e: logger.error(f"DB connection error: {e}. Attempting to reconnect..."); con.close(); await asyncio.sleep(5); con = get_db_connection()
        except Exception as e: logger.error(f"Error in DB writer loop: {e}", exc_info=True)
async def live_feed_loop(q):
    global live_bytes_per_second
    loop = asyncio.get_running_loop()
    while True:
        try:
            _session_id, packet_data = await loop.run_in_executor(None, q.get)
            live_bytes_per_second += packet_data.get('summary', {}).get('length', 0)
            await broadcast(packet_data)
        except queue.Empty: await asyncio.sleep(0.01)
        except Exception as e: logger.error(f"Error in live feed loop: {e}")
async def broadcast(message):
    if not clients: return
    message_json = json.dumps(message, default=str) # Use default=str to handle dates
    disconnected_clients = set()
    for client in clients:
        try: await client.send(message_json)
        except websockets.exceptions.ConnectionClosed: disconnected_clients.add(client)
    if disconnected_clients: clients.difference_update(disconnected_clients)
async def broadcast_sessions(): await broadcast({"type": "sessions_updated", "data": get_sessions()})
async def register(websocket):
    clients.add(websocket); logger.info(f"Client connected. Total clients: {len(clients)}")
    try:
        await websocket.send(json.dumps({"type": "interfaces", "data": get_if_list()}))
        await websocket.send(json.dumps({"type": "sessions", "data": get_sessions()}))
    except Exception as e: logger.error(f"Could not send initial data: {e}")
async def unregister(websocket):
    if websocket in clients: clients.remove(websocket); logger.info(f"Client disconnected. Total clients: {len(clients)}")

async def handler(websocket, path="/"):
    global sniffer_process, current_session_id, arp_cache, alert_thresholds
    await register(websocket)
    try:
        async for message in websocket:
            command = json.loads(message)
            action = command.get("action")
            if action == "START":
                if sniffer_process is None or not sniffer_process.is_alive():
                    if current_session_id is None: current_session_id = create_session(); arp_cache.clear()
                    if current_session_id is None: await websocket.send(json.dumps({"status": "error", "message": "Failed to create capture session."})); continue
                    interface, bpf_filter = command.get("interface", "wlan0mon"), command.get("filter", "")
                    sniffer_process = Process(target=sniffing_process_target, args=(interface, bpf_filter, packet_feed_queue, current_session_id))
                    sniffer_process.start()
                    await websocket.send(json.dumps({"status": "starting", "session_id": current_session_id})); await broadcast_sessions()
            elif action == "STOP":
                if sniffer_process and sniffer_process.is_alive():
                    sniffer_process.terminate(); sniffer_process.join(); sniffer_process = None; logger.info("Sniffer process stopped.")
                    await websocket.send(json.dumps({"status": "stopped"}))
            elif action == "END_SESSION":
                if current_session_id is not None:
                    logger.info(f"Ending session {current_session_id}...")
                    if sniffer_process and sniffer_process.is_alive(): sniffer_process.terminate(); sniffer_process.join(); sniffer_process = None
                    end_session_in_db(current_session_id); current_session_id = None
                    await websocket.send(json.dumps({"status": "session_ended"})); await broadcast_sessions()
            elif action == "GET_GLOBAL_ANALYSIS": await websocket.send(json.dumps({"type": "global_analysis_data", "data": get_global_analysis_data()}, default=str)) # MODIFIED
            elif action == "UPDATE_ALERT_THRESHOLDS": alert_thresholds.update(command.get("thresholds", {}))
            elif action == "GET_SESSION_PACKETS": session_id = command.get("session_id"); await websocket.send(json.dumps({"type": "session_packets", "data": get_packets_for_session(session_id)}))
            elif action == "DOWNLOAD_SESSION": session_id = command.get("session_id"); await websocket.send(json.dumps({"type": "session_download_data", "session_id": session_id, "data": get_packets_for_session(session_id)}))
            elif action == "DELETE_SESSION": session_id = command.get("session_id"); delete_session(session_id); await broadcast_sessions()
    finally: await unregister(websocket)

async def system_stats_loop():
    logger.info("Starting system stats loop...")
    while True:
        try:
            payload = {"type": "system_stats", "cpu": psutil.cpu_percent(), "memory": psutil.virtual_memory().percent}
            await broadcast(payload)
        except Exception as e: logger.error(f"Error in system_stats_loop: {e}")
        await asyncio.sleep(1)
async def alerts_checker_loop():
    global live_bytes_per_second
    logger.info("Starting alerts checker loop...")
    while True:
        await asyncio.sleep(5)
        if sniffer_process and sniffer_process.is_alive():
            cpu_usage = psutil.cpu_percent()
            if cpu_usage > alert_thresholds.get("cpu", 101):
                await broadcast({"type": "alert_triggered", "data": {"type": "High CPU Usage", "message": f"CPU has reached {cpu_usage}%"}})
            throughput_mbps = (live_bytes_per_second * 8) / (1000000 * 5)
            if throughput_mbps > alert_thresholds.get("throughput", 9999):
                 await broadcast({"type": "alert_triggered", "data": {"type": "High Throughput", "message": f"Throughput has reached {throughput_mbps:.2f} Mbps"}})
            live_bytes_per_second = 0

async def main():
    logger.info("Initializing database..."); init_db(); finish_all_open_sessions()
    asyncio.create_task(live_feed_loop(packet_feed_queue))
    asyncio.create_task(db_writer_loop(packet_feed_queue))
    asyncio.create_task(system_stats_loop())
    asyncio.create_task(alerts_checker_loop())
    async with websockets.serve(handler, HOST, PORT):
        logger.info(f"Server listening on ws://{HOST}:{PORT}")
        await asyncio.Future()

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: logger.info("Server shutting down.")
    finally:
        if sniffer_process and sniffer_process.is_alive():
            logger.info("Terminating sniffer process...")
            sniffer_process.terminate(); sniffer_process.join()