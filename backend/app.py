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