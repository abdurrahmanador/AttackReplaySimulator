#!/usr/bin/env python3
"""
AttackReplay Backend - FastAPI WebSocket server + detection + enrichment + port-scan + cache
Author: Abdur Rahman
"""

import os
import re
import json
import time
import sqlite3
import asyncio
from asyncio import gather
from functools import cache
from http.client import responses

import aiohttp
import socket
from datetime import datetime
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from websockets import broadcast

load_dotenv()

try:
    import geoip2.database as geoip2_db
except Exception:
    geoip2_db=None


#config
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY")
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH")
CACHE_DB_PATH = os.getenv("CACHE_DB_PATH", "intelsentry_cache.db")
LOG_FILE=os.getenv("LOG_FILE","sample.log")
PORT=int(os.getenv("PORT",8000))

#Runtime tuning
CACHE_TTL_SECONDS=int(os.getenv("CACHE_TTL_SECONDS",24*3600))
PORTSCAN_CONCURRENCY=int(os.getenv("PORTSCAN_CONCURRENCY",200))
PORTSCAN_TIMEOUT=float(os.getenv("PORTSCAN_TIMEOUT",1.0))
PORTSCAN_PORTS = [22, 80, 443, 3306, 8080, 3389, 5900, 21, 25]

#REGEX Detection rules
PAT_FAILED_LOGIN = re.compile(r"Failed password for .* from (\d{1,3}(?:\.\d{1,3}){3})")
PAT_SQLI = re.compile(r"(%27|\'|--|%23|#|\bunion\b|\bselect\b)", re.IGNORECASE)
PAT_ADMIN_PANEL = re.compile(r"(\/wp-admin|\/wp-login\.php|\/admin\b)", re.IGNORECASE)
PAT_IP = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
PAT_PORT_SCAN_HINT = re.compile(r"nmap|scan|SYN Scan|masscan", re.IGNORECASE)

#fastapi app+CORS
app=FastAPI(title="AttackReplay Backend")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


#SQLite Cache class
class CacheDB:

    def __init__(self, path:str=CACHE_DB_PATH):
        self.path = CACHE_DB_PATH
        self._ensure_schema()

    def _conn(self):
        return sqlite3.connect(self.path)

    def _ensure_schema(self):
        conn=self._conn()
        cur=conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS cache(
        provider TEXT NOT NULL,
        key TEXT NOT NULL,
        response TEXT,
        ts INTEGER,
        PRIMARY KEY(provider, key)
        );
        """)
        conn.commit()
        conn.close()

    def get(self,provider,key,ttl_seconds:str=CACHE_TTL_SECONDS)->Optional[Dict[str,any]]:
        conn=self._conn()
        cur=conn.cursor()
        cur.execute("SELECT response, ts FROM cache WHERE provider=? AND key=?", (provider, key))
        row=cur.fetchone()
        conn.close()
        if row:
            response_json,ts=row
            if (time.time()-ts)<=ttl_seconds:
                try:
                    return json.loads(response_json)
                except Exception:
                    return None

        return None

    def set(self,provider,key,obj:Dict[str,any]):
        conn=self._conn()
        cur=conn.cursor()
        cur.execute("INSERT OR REPLACE INTO cache(provider, key, response, ts) VALUES (?, ?, ?, ?)",
                    (provider, key, json.dumps(obj, ensure_ascii=False), int(time.time())))
        conn.commit()
        conn.close()

#Websocket Manager
class Broadcaster:

    def __init__(self):
        self._connections:List[WebSocket]=[]
        self.lock=asyncio.Lock()

    async def connect(self,ws:WebSocket):
        await ws.accept()
        async with self.lock:
            self._connections.append(ws)

    async def disconnect(self,ws:WebSocket):
        async with self.lock:
            if ws in self._connections:
                self._connections.remove(ws)

    async def broadcast(self,message:Dict[str,any]):
        payload=json.dumps(message,default=str)
        async with self.lock:
            stale=[]
            for ws in list(self._connections):
                try:
                    await ws.send_text(payload)
                except Exception:
                    stale.append(ws)
            for s in stale:
                if s in self._connections:
                    self._connections.remove(s)
broadcaster = Broadcaster()

#GeoIP helper
geo_reader=None
if GEOIP_DB_PATH and geoip2_db:
    try:
        geo_reader=geoip2_db.Reader(GEOIP_DB_PATH)
    except Exception:
        geo_reader=None

async def geo_lookup(ip:str)->Dict[str,any]:
    if geo_reader:
        try:
            r = geo_reader.city(ip)
            country = r.country.name or ""
            city = r.city.name or ""
            lat = getattr(r.location, "latitude", None)
            lon = getattr(r.location, "longitude", None)
            isp = ""  # MaxMind ASN DB needed for ASN/ISP, skip if not present
            return {"country": country, "city": city, "lat": lat, "lon": lon, "org": isp}
        except Exception:
            pass

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,org,message"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=6) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("status") == "success":
                        return {"country": data.get("country"), "city": data.get("city"),
                                "lat": data.get("lat"), "lon": data.get("lon"), "org": data.get("org")}
    except Exception:
        pass

    return {"country": None, "city": None, "lat": None, "lon": None, "org": None}

#HTTP adapters for providers
async def abuseipdb_check(ip: str) -> Dict[str, Any]:
    """Return AbuseIPDB 'data' dict or error dict. Requires ABUSEIPDB_KEY env var."""
    if not ABUSEIPDB_KEY:
        return {"skipped": True, "reason": "no-abuseipdb-key"}
    cached = cache.get("abuseipdb", ip)
    if cached:
        return {"cached": True, "data": cached}
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, params=params, timeout=15) as resp:
                text = await resp.text()
                if resp.status != 200:
                    return {"error": f"http_{resp.status}", "body": text}
                data = await resp.json()
                d = data.get("data", data)
                cache.set("abuseipdb", ip, d)
                return {"data": d}
    except Exception as e:
        return {"error": str(e)}

async def virustotal_check(ip: str) -> Dict[str, Any]:
    """Return VirusTotal v3 ip attributes or error dict. Requires VIRUSTOTAL_KEY env var."""
    if not VIRUSTOTAL_KEY:
        return {"skipped": True, "reason": "no-virustotal-key"}
    cached = cache.get("virustotal", ip)
    if cached:
        return {"cached": True, "data": cached}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_KEY}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=15) as resp:
                text = await resp.text()
                if resp.status != 200:
                    return {"error": f"http_{resp.status}", "body": text}
                data = await resp.json()
                attrs = data.get("data", {}).get("attributes", data)
                cache.set("virustotal", ip, attrs)
                return {"data": attrs}
    except Exception as e:
        return {"error": str(e)}

# Async port scanner (bounded concurrency)

async def scan_ports(ip:str, ports:List[int],concurrency:int=PORTSCAN_CONCURRENCY,timeout:float=PORTSCAN_TIMEOUT)->List[int]:
    open_ports=[]
    sem=asyncio.Semaphore(concurrency)

    async def probe(p):
        try:
            await sem.acquire()
            try:
                fut = asyncio.open_connection(host=ip, port=p)
                reader, writer = await asyncio.wait_for(fut, timeout=timeout)
                open_ports.append(p)
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
            finally:
                sem.release()
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return
        except Exception:
            return

    tasks=[asyncio.create_task(probe(p))for p in ports]
    await  asyncio.gather(*tasks)
    return sorted(open_ports)

#Detector(sync/async wrapper)
def make_event(event_type:str,src_ip:str,raw_line:str,severity:"medium")->Dict[str, Any]:
    return {
        "event_id": f"{int(time.time()*1000)}_{os.urandom(2).hex()}",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "src_ip": src_ip,
        "attack_type": event_type,
        "severity": severity,
        "raw": raw_line,
        "enriched": None
    }

async def enrich_and_scan(event:Dict[str, Any]) :
    ip = event.get("src_ip")
    if not ip:
        return

    #1) geo lookup
    geo=await geo_lookup(ip)
    event_enrich={"geo":geo}

    #2) provider checks concurrently
    tasks=[]
    if ABUSEIPDB_KEY:
        tasks.append(("abuseipdb", abuseipdb_check(ip)))
    else:
        tasks.append(("abuseipdb", asyncio.sleep(0, result={"skipped": True, "reason": "no-key"})))
    if VIRUSTOTAL_KEY:
        tasks.append(("virustotal", virustotal_check(ip)))
    else:
        tasks.append(("virustotal", asyncio.sleep(0, result={"skipped": True, "reason": "no-key"})))

    #run tasks concurrently:
    provider_results= {}

    for name,coro in tasks:
        try:
            res=await coro if asyncio.iscoroutine(coro) else coro
        except Exception as e:
            res = {"error": str(e)}
        provider_results[name] = res
    event_enrich["providers"]=provider_results

    #port scan
    open_ports=await scan_ports(ip, PORTSCAN_PORTS)
    event_enrich["open_ports"]=open_ports

    #attach and broadcast
    event["enriched"]=event_enrich
    await broadcaster.broadcast({"type": "event:update", "event": event})

#log tailer
async def tail_file_and_detect(path:str,poll_interval:float=0.5):
    """
       Tail a file and detect events line by line.
       If file doesn't exist, the function will return.
    """

    if not os.path.isfile(path):
        print(f"[tailer] log file not found: {path}")
        return
    print(f"[tailer] starting tail on {path}")

    with open(path,"r",encoding="utf-8",errors="replace") as f:
        f.seek(0,os.SEEK_END)
        while True:
            line=f.readline()
            if not line:
                await asyncio.sleep(poll_interval)
                continue
            line =line.strip()

            #detect pattern
            #1) Failed SSH login
            m=PAT_FAILED_LOGIN.search(line)
            if m:
                ip=m.group(1)
                ev=make_event("Failed SSH Login",ip,line,severity="high")
                asyncio.create_task(broadcaster.broadcast({"type": "event:new", "event": ev}))
                asyncio.create_task(enrich_and_scan(ev))
                continue

            #2) SQLi heuristic
            if PAT_SQLI.search(line):
                ip_m=PAT_IP.search(line)
                ip=ip_m.group(1) if ip_m else None
                ev = make_event("SQL Injection Attempt", ip or "unknown", line, severity="critical")
                asyncio.create_task(broadcaster.broadcast({"type": "event:new", "event": ev}))
                if ip:
                    asyncio.create_task(enrich_and_scan(ev))
                continue

            #3) Admin panel probe
            if PAT_ADMIN_PANEL.search(line):
                ip_m = PAT_IP.search(line)
                ip = ip_m.group(1) if ip_m else None
                ev = make_event("Admin Panel Probe", ip or "unknown", line, severity="medium")
                asyncio.create_task(broadcaster.broadcast({"type": "event:new", "event": ev}))
                if ip:
                    asyncio.create_task(enrich_and_scan(ev))
                continue

            # 4) port-scan hint strings
            if PAT_PORT_SCAN_HINT.search(line):
                ip_m = PAT_IP.search(line)
                ip = ip_m.group(1) if ip_m else None
                ev = make_event("Port Scan Detected", ip or "unknown", line, severity="low")
                asyncio.create_task(broadcaster.broadcast({"type": "event:new", "event": ev}))
                if ip:
                    asyncio.create_task(enrich_and_scan(ev))
                continue

#fastapi endpoints

@app.get("/health")
async def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat() + "Z"}

@app.websocket("/ws/events")
async def ws_endpoint(ws:WebSocket):
    await broadcaster.connect(ws)
    try:
        while True:
            msg=await ws.receive_text()
            await ws.send_text(json.dumps({"type": "server:echo", "msg": msg}))
    except WebSocketDisconnect:
        await broadcaster.disconnect(ws)

    except Exception:
        await broadcaster.disconnect(ws)
@app.on_event("startup")
async def start_tasks():
    await startup_event()

@app.post("/ingest")
async def ingest_log(request: Request, background: BackgroundTasks):
    """
    Accept POSTed log lines as JSON: {"line": "..."}
    Useful for LogSentry or other forwarders to push lines into detection.
    """
    body = await request.json()
    line = body.get("line")
    if not line:
        raise HTTPException(status_code=400, detail="missing 'line' in JSON")
    line = line.strip()
    m = PAT_FAILED_LOGIN.search(line)
    if m:
        ip = m.group(1)
        ev = make_event("Failed SSH Login", ip, line, severity="high")
        # broadcast immediately
        await broadcaster.broadcast({"type": "event:new", "event": ev})
        background.add_task(enrich_and_scan, ev)
        return JSONResponse({"status": "detected", "event": ev})
    if PAT_SQLI.search(line):
        ip_m = PAT_IP.search(line)
        ip = ip_m.group(1) if ip_m else None
        ev = make_event("SQL Injection Attempt", ip or "unknown", line, severity="critical")
        await broadcaster.broadcast({"type": "event:new", "event": ev})
        if ip:
            background.add_task(enrich_and_scan, ev)
        return JSONResponse({"status": "detected", "event": ev})
    if PAT_ADMIN_PANEL.search(line):
        ip_m = PAT_IP.search(line)
        ip = ip_m.group(1) if ip_m else None
        ev = make_event("Admin Panel Probe", ip or "unknown", line, severity="medium")
        await broadcaster.broadcast({"type": "event:new", "event": ev})
        if ip:
            background.add_task(enrich_and_scan, ev)
        return JSONResponse({"status": "detected", "event": ev})

    # else: nothing suspicious
    return JSONResponse({"status": "ok", "msg": "no rule matched"})

#Startup tasks:
async def startup_event():
    loop = asyncio.get_event_loop()
    if os.path.exists(LOG_FILE):
        print(f"[startup] launching tailer for {LOG_FILE}")
        loop.create_task(tail_file_and_detect(LOG_FILE))
    else:
        print(f"[startup] LOG_FILE env {LOG_FILE} not found; run generator or create a log file for demo")
