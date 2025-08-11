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