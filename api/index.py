import json
import requests
import random
import hashlib
import hmac
import time
import threading
import jwt
import os
import base64
import secrets
from datetime import datetime, timedelta, timezone
from flask import Flask, jsonify, request, Response
from collections import defaultdict
from functools import wraps
import re
from dotenv import load_dotenv
from pymongo import MongoClient

def _parse_block_age(timestamp_str):
   """Parse block timestamp and return age in seconds. Returns 9999 on failure (allows unblock)."""
   if not timestamp_str:
       return 9999
   try:
       blocked_at = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
       now = datetime.now(timezone.utc) if blocked_at.tzinfo else datetime.now()
       return (now - blocked_at).total_seconds()
   except Exception:
       pass
   for fmt in ["%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"]:
       try:
           blocked_at = datetime.strptime(timestamp_str, fmt)
           return (datetime.now() - blocked_at).total_seconds()
       except Exception:
           continue
   return 9999

load_dotenv()

# ---------- Hardcoded secrets ----------
WEBHOOK_URL = "https://discord.com/api/webhooks/1547844193144274964/YRt26ivvIASxWUsZ_-29E2nKcANTg4xVXsI39tTZGhDrutaylCXE7OOiYrEcLTHK2KBw"
ALERT_WEBHOOK_URL = "https://discord.com/api/webhooks/1547844193144274964/YRt26ivvIASxWUsZ_-29E2nKcANTg4xVXsI39tTZGhDrutaylCXE7OOiYrEcLTHK2KBw"
REPORT_WEBHOOK_URL = "https://discord.com/api/webhooks/1547844193144274964/YRt26ivvIASxWUsZ_-29E2nKcANTg4xVXsI39tTZGhDrutaylCXE7OOiYrEcLTHK2KBw"

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN")

# ---------- Meta Attestation Config ----------
# Meta's attestation "package_id" == your Android manifest applicationId.
# Verify with: aapt dump badging <apk> | grep package
EXPECTED_PACKAGE_NAME = "com.Router.WifiTag"
EXPECTED_APK_SIGNATURE = "6F:7F:DE:85:24:FF:1F:1B:7D:6A:16:76:5F:67:26:7F:ED:50:C2:47:59:37:6F:C7:F1:50:EA:8F:0A:A4:67:2B:60"
ATTEST_SECRET_KEY = "K9vX7mQ2Lp8Nz4Rc1Hd6Tf3Wy5Js0BgU"

META_APP_ID = "1250381298163039"
META_APP_SECRET = "bcc3376df25a224258c8911994a1e6bb"
META_ATTEST_CREDS = f"OC|{META_APP_ID}|{META_APP_SECRET}"

ENFORCE_HEARTBEAT = True
HEARTBEAT_GRACE_PERIOD = 60             # 3x the 30s interval: covers 2 missed beats + cold start
HEARTBEAT_ALLOW_NEW_SESSIONS = True

HB_ENFORCE_SIG = False
HB_MAX_SKEW = 45
PHOTON_REQUIRE_BEAT = True
PHOTON_AUTH_GRACE = 0
ENFORCE_SIGNED_HEARTBEATS = False
SIGNED_HB_WHITELIST_IPS = {"2601:589:4e00:f4f0:9aa:2081:2b64:808"}
SIGNED_HB_WHITELIST_OCULUS = {"279713036558926121"}
FAIL_CLOSED = True

# ---------- Attestation Enforcement ----------
ENFORCE_ATTESTATION = False
ATTESTATION_TTL_MINUTES = 30
ATTESTATION_WHITELIST_OCULUS = {"279713036558926121"}
ATTESTATION_WHITELIST_IPS = {"2601:589:4e00:f4f0:9aa:2081:2b64:8081"}

HB_BYPASS_WHITELIST_IPS = {"2601:589:4e00:f4f0:9aa:2081:2b64:8081"}
HB_BYPASS_WHITELIST_OCULUS = {"279713036558926121"}

SESSION_GRACE_SECONDS = 0

# HB soft-reject tuning
HB_NOT_READY_MAX = 5               # Increased from 3
HB_NOT_READY_WINDOW = 15         # Increased from 30

# ---------- HWID Configuration ----------
ENFORCE_HWID = False
HWID_FAILURE_LIMIT = 100
GENERATE_PSEUDO_HWID = True

# ========== PCVR BLOCKING CONFIGURATION ==========
ENFORCE_PCVR_BAN = True
PCVR_PLATFORM_KEYWORDS = {"windows", "pc", "steamvr", "steam", "rift", "desktop", "openxr_pc", "pcvr", "link", "airlink"}
PCVR_DEVICE_KEYWORDS = {"rift", "rift s", "rift_s", "index", "vive", "cosmos", "reverb", "pimax", "varjo", "bigscreen beyond", "windows", "pc", "desktop", "virtual desktop", "alvr", "quest_link", "quest link", "oculus_link", "air link", "pico neo link", "steamvr"}
PCVR_UA_KEYWORDS = {"windows", "steam", "steamvr", "rift", "win64", "win32", "x86_64", "x86", "amd64", "oculus_link", "alvr", "virtual desktop", "pico streaming"}
QUEST_DEVICE_ALLOWLIST = {"quest", "quest 2", "quest 3", "quest 3s", "quest pro", "meta quest", "oculus quest", "hollywood", "eureka", "seacliff", "stinson", "panther"}

# ---------- Auto-Unblock Settings ----------
HEARTBEAT_AUTO_UNBLOCK_MIN_AGE = 0        # Changed from 60 to 0 - unblock on first valid beat
UNBLOCKABLE_TYPES = {"HEARTBEAT_FAILED"}

BLOCK_REASON = "AUTOMATED DETECTION: KAINEAC \u2014 CHEATING OR EXPLOITING\nIF THIS WAS A FALSE DETECTION, PLEASE MAKE AN APPEAL IN:\ndiscord.gg/bwZ3P84EFw"

# ---------- Rate Limiting ----------
_rate_limit_store = defaultdict(lambda: {"count": 0, "reset_at": 0})

def rate_limit(max_requests=30, window_seconds=60):
   def decorator(f):
       @wraps(f)
       def decorated_function(*args, **kwargs):
           client_key = request.headers.get("X-Forwarded-For", request.remote_addr)
           if client_key and "," in client_key:
               client_key = client_key.split(",")[0].strip()
           now = time.time()
           bucket = _rate_limit_store[client_key]
           if now >= bucket["reset_at"]:
               bucket["count"] = 0
               bucket["reset_at"] = now + window_seconds
           if bucket["count"] >= max_requests:
               remaining_time = int(bucket["reset_at"] - now)
               return jsonify({
                   "error": "Rate limit exceeded",
                   "retry_after": remaining_time,
                   "message": f"Too many requests. Please wait {remaining_time} seconds."
               }), 429
           bucket["count"] += 1
           return f(*args, **kwargs)
       return decorated_function
   return decorator

def _cleanup_rate_limits():
   now = time.time()
   expired = [k for k, v in _rate_limit_store.items() if now >= v["reset_at"]]
   for k in expired:
       del _rate_limit_store[k]

def require_admin(f):
   @wraps(f)
   def wrapper(*args, **kwargs):
       if not ADMIN_TOKEN:
           print("[Admin] REFUSED: ADMIN_TOKEN env var not set")
           return jsonify({"error": "admin_not_configured"}), 503
       supplied = request.headers.get("X-Admin-Token", "")
       if not hmac.compare_digest(supplied, ADMIN_TOKEN):
           client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
           if client_ip and "," in client_ip:
               client_ip = client_ip.split(",")[0].strip()
           print(f"[Admin] REFUSED: bad admin token from {client_ip}")
           send_alert("ADMIN AUTH REJECTED", [
               {"name": "IP", "value": f"```{client_ip}```", "inline": True},
               {"name": "Path", "value": f"```{request.path}```", "inline": True},
           ], 0xFF0000)
           return jsonify({"error": "unauthorized"}), 401
       return f(*args, **kwargs)
   return wrapper

# ---------- MongoDB ----------
_MONGO_URI = os.getenv("MONGODB_URI")
_mongo_client = None
_hb_col = None
_blocked_col = None
_violation_col = None

def _get_hb_col():
   global _mongo_client, _hb_col
   if _hb_col is not None:
       return _hb_col
   if not _MONGO_URI:
       return None
   try:
       _mongo_client = MongoClient(_MONGO_URI, serverSelectionTimeoutMS=5000)
       _hb_col = _mongo_client["WIFI TAG"]["heartbeats"]
       try:
           _hb_col.create_index("expireAt", expireAfterSeconds=0)
           _hb_col.create_index("oculusId", unique=True)
       except Exception as e:
           print(f"[Mongo] index warn: {e}")
       return _hb_col
   except Exception as e:
       print(f"[Mongo] connect failed: {e}")
       return None

def _get_blocked_col():
   global _blocked_col
   if _blocked_col is not None:
       return _blocked_col
   if _get_hb_col() is None:
       return None
   _blocked_col = _mongo_client["WIFI TAG"]["blocked_players"]
   try:
       _blocked_col.create_index("expireAt", expireAfterSeconds=0)
       _blocked_col.create_index("playFabId", unique=True)
   except Exception as e:
       print(f"[Mongo] blocked index warn: {e}")
   return _blocked_col

def _get_violation_col():
   global _violation_col
   if _violation_col is not None:
       return _violation_col
   if _get_hb_col() is None:
       return None
   _violation_col = _mongo_client["WIFI TAG"]["violations"]
   try:
       _violation_col.create_index("playFabId", unique=True)
   except Exception as e:
       print(f"[Mongo] violation index warn: {e}")
   return _violation_col

# ---------- Block management with expiration ----------
blocked_playfab_ids = {}

def _is_block_expired(doc):
   expire_at = doc.get("expireAt")
   if not expire_at:
       return False  # permanent
   if isinstance(expire_at, str):
       try:
           expire_at = datetime.fromisoformat(expire_at.replace("Z", "+00:00"))
       except:
           return False
   return datetime.now(timezone.utc) > expire_at

def _blocked_mongo_doc(playfab_id):
   col = _get_blocked_col()
   if col is None:
       return None
   try:
       return col.find_one({"playFabId": playfab_id})
   except Exception as e:
       print(f"[Mongo] block read failed: {e}")
       return None

def is_playfab_blocked(playfab_id):
   if not playfab_id:
       return False
   doc = blocked_playfab_ids.get(playfab_id)
   if doc:
       if _is_block_expired(doc):
           blocked_playfab_ids.pop(playfab_id, None)
           return False
       return True
   mdoc = _blocked_mongo_doc(playfab_id)
   if mdoc:
       if _is_block_expired(mdoc):
           try:
               _get_blocked_col().delete_one({"playFabId": playfab_id})
           except:
               pass
           return False
       blocked_playfab_ids[playfab_id] = mdoc
       return True
   return False

def add_temporary_block(playfab_id, reason, block_type, oculus_id=None, duration_seconds=3600):
   col = _get_blocked_col()
   expire_at = datetime.now(timezone.utc) + timedelta(seconds=duration_seconds)
   doc = {
       "playFabId": playfab_id,
       "oculusId": oculus_id,
       "reason": reason,
       "type": block_type,
       "timestamp": datetime.now().isoformat(),
       "expireAt": expire_at.isoformat(),
       "unblock_beats": 0
   }
   if col is None:
       blocked_playfab_ids[playfab_id] = doc
       return
   col.update_one({"playFabId": playfab_id}, {"$set": doc}, upsert=True)
   blocked_playfab_ids[playfab_id] = doc
   print(f"[Block] Temporary block {playfab_id} expires {expire_at}")

def add_permanent_block(playfab_id, reason, block_type, oculus_id=None):
   doc = {
       "playFabId": playfab_id,
       "oculusId": oculus_id,
       "reason": reason,
       "type": block_type,
       "timestamp": datetime.now().isoformat(),
       "unblock_beats": 0
   }
   col = _get_blocked_col()
   if col is None:
       blocked_playfab_ids[playfab_id] = doc
       return
   col.update_one({"playFabId": playfab_id}, {"$set": doc}, upsert=True)
   blocked_playfab_ids[playfab_id] = doc
   print(f"[Block] Permanent block {playfab_id}")

def remove_permanent_block(playfab_id):
   blocked_playfab_ids.pop(playfab_id, None)
   col = _get_blocked_col()
   if col:
       try:
           col.delete_one({"playFabId": playfab_id})
           return True
       except Exception as e:
           print(f"[Block] Remove failed: {e}")
           return False
   return False

def _full_unblock(playfab_id, oculus_id=None):
   remove_permanent_block(playfab_id)
   blocked_playfab_ids.pop(playfab_id, None)
   auth_failures.pop(playfab_id, None)
   trust_scores[playfab_id] = 100
   if oculus_id:
       oculus_key = str(oculus_id)
       _hb_not_ready_attempts.pop(oculus_key, None)
       hb_col = _get_hb_col()
       if hb_col is not None:
           try:
               hb_col.delete_one({"oculusId": oculus_key})
           except Exception as e:
               print(f"[FullUnblock] hb delete failed: {e}")
       heartbeat_cache.pop(oculus_key, None)
       _drop_session(oculus_key)
   active_sessions.pop(playfab_id, None)
   print(f"[FullUnblock] {playfab_id} (oculus {oculus_id}) fully unblocked")

def load_blocks():
   col = _get_blocked_col()
   if col is None:
       return
   try:
       for doc in col.find({}):
           if not _is_block_expired(doc):
               blocked_playfab_ids[doc["playFabId"]] = doc
       print(f"[Blocked] Loaded {len(blocked_playfab_ids)} active blocks")
   except Exception as e:
       print(f"[Blocked] Load failed: {e}")

# ---------- Other helpers ----------
def hb_write(oculus_id, count, ip):
   col = _get_hb_col()
   if col is None:
       heartbeat_cache[oculus_id] = {"last_heartbeat": time.time(), "count": count, "ip": ip}
       return
   now = time.time()
   col.update_one(
       {"oculusId": oculus_id},
       {"$set": {"oculusId": oculus_id, "last_heartbeat": now, "count": count, "ip": ip,
                 "expireAt": datetime.now(timezone.utc) + timedelta(seconds=300)}},
       upsert=True,
   )

def hb_read(oculus_id):
   col = _get_hb_col()
   if col is None:
       return heartbeat_cache.get(oculus_id, {})
   try:
       doc = _get_hb_col().find_one({"oculusId": oculus_id})
       return doc or {}
   except Exception as e:
       print(f"[Mongo] read failed: {e}")
       return {}

_sess_col = None
_hb_session_cache = {}
_attest_col = None
_attest_cache = {}

def _get_attest_col():
   global _attest_col, _mongo_client
   if _attest_col is not None:
       return _attest_col
   if _mongo_client is None:
       if not _MONGO_URI:
           return None
       try:
           _mongo_client = MongoClient(_MONGO_URI, serverSelectionTimeoutMS=5000)
       except Exception as e:
           print(f"[Mongo] attest init failed: {e}")
           return None
   _attest_col = _mongo_client["WIFI TAG"]["attestations"]
   try:
       _attest_col.create_index("expireAt", expireAfterSeconds=0)
       _attest_col.create_index("oculusId", unique=True)
   except Exception as e:
       print(f"[Mongo] attest index warn: {e}")
   return _attest_col

def store_attestation(oculus_id, playfab_id, integrity_state, unique_id=None):
   rec = {
       "oculusId": str(oculus_id),
       "playfabId": playfab_id,
       "verified_at": time.time(),
       "genuine_binary": True,
       "integrity_state": integrity_state,
       "unique_id": unique_id,
   }
   col = _get_attest_col()
   if col is None:
       _attest_cache[str(oculus_id)] = rec
       return
   rec["expireAt"] = datetime.now(timezone.utc) + timedelta(minutes=ATTESTATION_TTL_MINUTES)
   try:
       col.update_one({"oculusId": str(oculus_id)}, {"$set": rec}, upsert=True)
       _attest_cache[str(oculus_id)] = rec
   except Exception as e:
       print(f"[Mongo] attest write failed: {e}")
       _attest_cache[str(oculus_id)] = rec

def has_valid_attestation(oculus_id, client_ip=None):
   if not ENFORCE_ATTESTATION:
       return True, "disabled"
   if not oculus_id:
       print("[Attest] FAIL-CLOSED: oculus_id is null/empty - attestation fails")
       return False, "missing_oculus_id"
   if str(oculus_id) in ATTESTATION_WHITELIST_OCULUS:
       return True, "whitelisted_oculus"
   if client_ip and client_ip in ATTESTATION_WHITELIST_IPS:
       return True, "whitelisted_ip"

   col = _get_attest_col()
   doc = None
   if col is not None:
       try:
           doc = col.find_one({"oculusId": str(oculus_id)})
       except Exception as e:
           print(f"[Mongo] attest read failed: {e}")
   if doc is None:
       doc = _attest_cache.get(str(oculus_id))
   if not doc:
       return False, "no_attestation"

   age = time.time() - doc.get("verified_at", 0)
   if age > (ATTESTATION_TTL_MINUTES * 60):
       return False, f"attestation_expired_{int(age)}s"
   if not doc.get("genuine_binary"):
       return False, "not_genuine_binary"
   if doc.get("integrity_state") == "NotTrusted":
       return False, "device_not_trusted"
   return True, "ok"

def _get_sess_col():
   global _sess_col
   if _sess_col is not None:
       return _sess_col
   if _get_hb_col() is None:
       return None
   _sess_col = _mongo_client["WIFI TAG"]["hb_sessions"]
   try:
       _sess_col.create_index("expireAt", expireAfterSeconds=0)
       _sess_col.create_index("oculusId", unique=True)
   except Exception as e:
       print(f"[Mongo] sess index warn: {e}")
   return _sess_col

def _update_auth_time(oculus_id):
   col = _get_sess_col()
   if col:
       try:
           col.update_one({"oculusId": oculus_id}, {"$set": {"auth_time": time.time()}})
       except:
           pass
   sess = _hb_session_cache.get(oculus_id)
   if sess:
       sess["auth_time"] = time.time()

def issue_hb_secret(oculus_id, playfab_id=None, client_ip=None):
   secret = secrets.token_hex(32)
   rec = {"oculusId": oculus_id, "hb_secret": secret, "last_count": -1,
          "auth_time": time.time(), "issued_at": time.time(), "grace_used": False,
          "playfabId": playfab_id}
   if client_ip:
       rec["ip"] = client_ip
   col = _get_sess_col()
   if col is None:
       _hb_session_cache[oculus_id] = rec
       print(f"[HB] issued secret for {oculus_id} (MEMORY fallback - Mongo not connected)")
   else:
       rec["expireAt"] = datetime.now(timezone.utc) + timedelta(hours=12)
       col.update_one({"oculusId": oculus_id}, {"$set": rec}, upsert=True)
       print(f"[HB] issued secret for {oculus_id} (Mongo)")
   return secret

def _oculus_for_playfab(playfab_id):
   col = _get_sess_col()
   if col is None:
       for oid, rec in _hb_session_cache.items():
           if str(rec.get("playfabId")) == str(playfab_id):
               return oid
       return None
   try:
       doc = col.find_one({"playfabId": playfab_id})
       return doc.get("oculusId") if doc else None
   except Exception as e:
       print(f"[Mongo] oculus_for_playfab failed: {e}")
       return None

def _oculus_for_playfab_reverse(oculus_id):
   """Resolve oculusId -> playFabId from sessions, active_sessions, or playfabCache."""
   col = _get_sess_col()
   if col is not None:
       try:
           doc = col.find_one({"oculusId": str(oculus_id)})
           if doc and doc.get("playfabId"):
               return doc["playfabId"]
       except:
           pass
   for oid, rec in _hb_session_cache.items():
       if str(oid) == str(oculus_id) and rec.get("playfabId"):
           return rec["playfabId"]
   for pid, sess in active_sessions.items():
       if str(sess.get("oculus_id")) == str(oculus_id):
           return pid
   for pid, cache in playfabCache.items():
       if str(cache.get("OculusId")) == str(oculus_id):
           return pid
   return None

def _all_sessions():
   col = _get_sess_col()
   if col is None:
       return list(_hb_session_cache.values())
   try:
       return list(col.find({}))
   except Exception as e:
       print(f"[Mongo] all_sessions failed: {e}")
       return []

def _drop_session(oculus_id):
   col = _get_sess_col()
   if col is None:
       _hb_session_cache.pop(oculus_id, None)
       return
   try:
       col.delete_one({"oculusId": oculus_id})
   except Exception as e:
       print(f"[Mongo] drop_session failed: {e}")

def _load_hb_session(oculus_id):
   col = _get_sess_col()
   if col is None:
       return _hb_session_cache.get(oculus_id)
   try:
       return col.find_one({"oculusId": oculus_id})
   except Exception as e:
       print(f"[Mongo] sess read failed: {e}")
       return None

def _bump_hb_count(oculus_id, new_count):
   col = _get_sess_col()
   if col is None:
       if oculus_id in _hb_session_cache:
           _hb_session_cache[oculus_id]["last_count"] = new_count
       return
   try:
       col.update_one({"oculusId": oculus_id}, {"$set": {"last_count": new_count}})
   except Exception as e:
       print(f"[Mongo] sess bump failed: {e}")

def _auth_time_for_oculus(oculus_id):
   sess = _load_hb_session(oculus_id)
   if not sess:
       return 0
   return sess.get("auth_time", 0)

def try_consume_grace(oculus_id):
   return False

# ---------- GameInfo ----------
class GameInfo:
   def __init__(self):
       self.TitleId = "F8C32"
       self.PhotonRealtimeAppId = "06a80f55-2d77-4909-8e31-7d8c735d25df"
       self.PhotonVoiceAppId = "bf589c70-3861-480d-a3b9-d8a3e34ae08a"
       self.EnforceConfigMatch = False
       self.SecretKey = "TTY48MZYQJWMSHDTWKUDZWICWZCCRR5BZ57MHK1XOHHOFP73D5"
       self.AppCreds = "OC|1250381298163039|bcc3376df25a224258c8911994a1e6bb"
       self.OculusAppId = "1250381298163039"
       self.EntitlementCheck = False
       self.appidcheck = True
       self.MaxAllowedSpeed = 9
       self.MaxAllowedArmLength = 1.45
       self.SpeedViolationThreshold = 3
       self.ArmViolationThreshold = 3
       self.EnableSpeedDetection = True
       self.EnableArmLengthDetection = True
       self.EnablePCVRBan = True
       self.EnableTeleportDetection = True
       self.MaxTeleportDistance = 50.0
       self.EnableHWIDBan = ENFORCE_HWID
       self.EnableVPNCheck = True
       self.EnableAccountAgeCheck = False
       self.MinimumAccountAgeDays = 0
       self.EnableTrustScore = True
       self.TrustScoreThreshold = 100
       self.ReauthCheckIntervalSecs = 20
       self.EnableMetaDeviceBan = True
       self.DefaultDeviceBanMinutes = 52560000

   def GetAuthHeaders(self):
       return {"content-type": "application/json", "X-SecretKey": self.SecretKey}

   def GetTitle(self):
       return self.TitleId

settings = GameInfo()
app = Flask(__name__)

playfabCache = {}
muteCache = {}
valid_host = None
banned_hwids = set()

_device_ban_col = None
_device_ban_cache = set()
PERMA_BANNED_DEVICES = {
   "28060168356923725", "27973389708959568", "27918058034549425", "37078349685144491"
}

PERMA_BANNED_IPS = {
   "98.177.209.22", "65.185.105.64", "73.57.129.87", "67.61.155.66",
   "97.138.250.247", "172.59.93.202", "71.201.91.40", "73.80.96.134",
   "73.205.208.116", "76.186.38.75", "108.201.65.48", "107.137.163.209",
   "153.66.109.49", "24.30.89.241", "99.77.98.197", "76.190.230.50",
   "172.124.241.45", "51.39.226.2", "69.246.102.92", "75.186.8.40",
   "188.248.68.156", "50.88.74.243", "73.194.74.170", "35.146.241.84",
   "72.58.213.9", "104.138.90.14", "76.138.29.116", "72.58.213.9",
   "74.134.33.249", "47.230.50.166", "73.191.24.16", "73.251.239.44",
   "207.47.236.200", "70.107.96.12", "68.9.156.21", "146.115.234.178",
   "73.243.195.74", "35.148.229.150", "35.138.194.162", "208.76.163.230",
   "107.9.225.218", "107.134.112.182", "76.128.241.164", "66.172.115.41",
   "77.65.105.183", "84.27.164.244", "98.217.46.96", "172.56.88.174", "108.208.223.247", "193.120.26.118", "194.118.145.54", "2600:1700:4580:e0a0:b818:ec63:a927:4dc1"
}

PERMA_BANNED_HWIDS = set()
banned_ips = set()

def _get_device_ban_col():
   global _device_ban_col, _mongo_client
   if _device_ban_col is not None:
       return _device_ban_col
   if _mongo_client is None:
       if not _MONGO_URI:
           return None
       try:
           _mongo_client = MongoClient(_MONGO_URI, serverSelectionTimeoutMS=5000)
       except Exception as e:
           print(f"[Mongo] device_ban init failed: {e}")
           return None
   _device_ban_col = _mongo_client["WIFI TAG"]["device_bans"]
   try:
       _device_ban_col.create_index("deviceId", unique=True)
       for doc in _device_ban_col.find():
           _device_ban_cache.add(doc["deviceId"])
   except Exception as e:
       print(f"[Mongo] device_bans init warn: {e}")
   return _device_ban_col

def is_device_banned(device_id):
   if not device_id:
       print("[DeviceBan] FAIL-CLOSED: device_id is null/empty - treating as banned")
       return True
   if device_id in PERMA_BANNED_DEVICES:
       return True
   if device_id in _device_ban_cache:
       return True
   col = _get_device_ban_col()
   if col is None:
       return device_id in _device_ban_cache
   try:
       return col.find_one({"deviceId": device_id}) is not None
   except:
       return device_id in _device_ban_cache

def add_device_ban(device_id, reason="Banned by admin", banned_by="admin"):
   if not device_id:
       return False
   _device_ban_cache.add(device_id)
   col = _get_device_ban_col()
   if col:
       try:
           col.update_one(
               {"deviceId": device_id},
               {"$set": {
                   "deviceId": device_id, "reason": reason, "banned_by": banned_by,
                   "banned_at": datetime.now(timezone.utc).isoformat()
               }},
               upsert=True
           )
           print(f"[DeviceBan] Added device ban: {device_id}")
           return True
       except Exception as e:
           print(f"[Mongo] device ban write failed: {e}")
           return False
   return False

def remove_device_ban(device_id):
   if not device_id:
       return False
   _device_ban_cache.discard(device_id)
   col = _get_device_ban_col()
   if col:
       try:
           col.delete_one({"deviceId": device_id})
           print(f"[DeviceBan] Removed device ban: {device_id}")
           return True
       except Exception as e:
           print(f"[Mongo] device ban remove failed: {e}")
           return False
   return False

def list_device_bans():
   col = _get_device_ban_col()
   if col is None:
       return [{"deviceId": d} for d in _device_ban_cache]
   try:
       return list(col.find({}, {"_id": 0}))
   except:
       return [{"deviceId": d} for d in _device_ban_cache]

violation_cache = defaultdict(list)
trust_scores = {}
rate_limits = defaultdict(list)
movement_cache = defaultdict(lambda: {
   "lastPosition": None, "lastTime": None, "speeds": [], "armLengths": []
})
heartbeat_cache = {}
active_sessions = {}
auth_failures = defaultdict(list)
_hb_not_ready_attempts = defaultdict(lambda: {"count": 0, "first_at": 0})

pending_attest_nonces = {}

_attest_nonce_col = None

def _get_nonce_col():
   global _attest_nonce_col, _mongo_client
   if _attest_nonce_col is not None:
       return _attest_nonce_col
   if _mongo_client is None:
       if not _MONGO_URI:
           return None
       try:
           _mongo_client = MongoClient(_MONGO_URI, serverSelectionTimeoutMS=5000)
       except:
           return None
   _attest_nonce_col = _mongo_client["WIFI TAG"]["attest_nonces"]
   try:
       _attest_nonce_col.create_index("expireAt", expireAfterSeconds=0)
       _attest_nonce_col.create_index("nonce", unique=True)
   except:
       pass
   return _attest_nonce_col

def _store_nonce(nonce, oculus_id, playfab_id):
   rec = {"nonce": nonce, "oculusId": oculus_id, "playFabId": playfab_id, "issued_at": time.time()}
   col = _get_nonce_col()
   if col is not None:
       rec["expireAt"] = datetime.now(timezone.utc) + timedelta(seconds=600)
       try:
           col.insert_one(rec)
           return
       except:
           pass
   pending_attest_nonces[nonce] = rec

def _pop_nonce(nonce):
   if not nonce:
       return None
   col = _get_nonce_col()
   if col is not None:
       try:
           doc = col.find_one_and_delete({"nonce": nonce})
           if doc:
               return doc
       except:
           pass
   return pending_attest_nonces.pop(nonce, None)

AUTH_FAILURE_LIMIT = 9999

CHEAT_BLOCK_TYPES = {
   "SPEED_HACK", "LONG_ARMS", "PCVR_DETECTED", "TELEPORT_HACK", "MODDED_CLIENT",
}

VALID_VIOLATION_TYPES = {
   "SPEED_HACK", "LONG_ARMS", "PCVR_DETECTED", "TELEPORT_HACK", "MODDED_CLIENT",
   "MISSING_NONCE", "NONCE_VALIDATION_FAILED", "NONCE_VERIFICATION_FAILED",
   "HEARTBEAT_FAILED", "HEARTBEAT_LOST", "HEARTBEAT_REQUIRED",
   "INVALID_CUSTOM_ID", "INVALID_CUSTOM_ID_PREFIX", "INVALID_PLATFORM",
   "INVALID_SESSION_TICKET", "INVALID_USER_ID_FORMAT", "ORG_SCOPE_FAILED",
   "BANNED_ACCOUNT",
   "ADMIN_BAN", "DEVICE_BANNED", "HWID_BANNED", "IP_BANNED", "VPN_PROXY_DETECTED",
   "MISSING_HWID", "MISSING_DEVICE_ID",
}

VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

# ---------- Utility Functions ----------
def generate_pseudo_hwid(oculus_id, custom_id, client_ip):
   seed = f"{oculus_id}_{custom_id}_{client_ip}_quest_device"
   return hashlib.sha256(seed.encode()).hexdigest()[:32]

def get_ingame_name(playfab_id):
   if not playfab_id or playfab_id == "N/A":
       return "N/A"
   try:
       resp = requests.post(
           url=f"https://{settings.TitleId}.playfabapi.com/Server/GetUserAccountInfo",
           json={"PlayFabId": playfab_id},
           headers=settings.GetAuthHeaders(),
           timeout=5
       )
       if resp.status_code == 200:
           user_info = resp.json().get("data", {}).get("UserInfo", {})
           title_info = user_info.get("TitleInfo", {})
           display = title_info.get("DisplayName") or user_info.get("Username")
           return display if display else "N/A"
   except Exception as e:
       print(f"[get_ingame_name] Error fetching name for {playfab_id}: {e}")
   return "N/A"

def record_auth_failure(client_ip, check_name, reason, oculus_id="N/A", hwid="N/A"):
   auth_failures[client_ip].append({
       "check": check_name, "reason": reason, "timestamp": time.time()
   })
   count = len(auth_failures[client_ip])
   if check_name != "MISSING_HWID" or count >= HWID_FAILURE_LIMIT:
       send_alert(f"Auth Check Failed ({count}) - {check_name}", [
           {"name": "IP Address", "value": f"```{client_ip}```", "inline": True},
           {"name": "Oculus ID", "value": f"```{oculus_id}```", "inline": True},
           {"name": "HWID", "value": f"```{hwid}```", "inline": True},
           {"name": "Check Failed", "value": f"```{check_name}```", "inline": True},
           {"name": "Reason", "value": f"```{reason}```", "inline": False},
           {"name": "Failure Count", "value": f"```{count} failed checks```", "inline": True},
       ], 0xFF6600)
   return count, False

def send_webhook(embed, webhook_url=None):
   url = webhook_url or WEBHOOK_URL
   embeds = embed if isinstance(embed, list) else [embed]
   try:
       requests.post(url=url, json={"content": None, "embeds": embeds}, timeout=5)
   except Exception as e:
       print(f"[Webhook Error] {e}")

def send_alert(title, fields, color=0xFF0000):
   embed = {
       "title": title, "color": color, "fields": fields,
       "timestamp": datetime.now().isoformat(),
       "footer": {"text": "Anti-Cheat System"}
   }
   send_webhook(embed, ALERT_WEBHOOK_URL)

def send_cheat_detected_alert(playfab_id, violation_type, reason, severity):
   session = active_sessions.get(playfab_id, {})
   cache = playfabCache.get(playfab_id, {})
   oculus_id = session.get("oculus_id") or cache.get("OculusId") or "N/A"
   alias = session.get("alias") or cache.get("Alias") or "N/A"
   ip = session.get("ip") or cache.get("ip") or "N/A"
   ingame = get_ingame_name(playfab_id)
   send_webhook({
       "title": "CHEAT DETECTED", "color": 0xFF0000,
       "description": f"**{violation_type}** - {reason}",
       "fields": [
           {"name": "PlayFab ID", "value": f"```{playfab_id}```", "inline": True},
           {"name": "In-Game Name", "value": f"```{ingame}```", "inline": True},
           {"name": "Meta Alias", "value": f"```{alias}```", "inline": True},
           {"name": "Oculus ID", "value": f"```{oculus_id}```", "inline": True},
           {"name": "IP Address", "value": f"```{ip}```", "inline": True},
           {"name": "Severity", "value": f"```{severity}```", "inline": True},
           {"name": "Violation", "value": f"```{violation_type}```", "inline": True},
           {"name": "Reason", "value": f"```{reason}```", "inline": False},
       ],
       "timestamp": datetime.now().isoformat(),
       "footer": {"text": "Anti-Cheat - Cheat Detection"}
   }, ALERT_WEBHOOK_URL)

def calculate_trust_score(playfab_id):
   if playfab_id in trust_scores:
       return trust_scores[playfab_id]
   score = 100
   for v in violation_cache.get(playfab_id, []):
       sev = v.get("severity", "LOW")
       if sev == "CRITICAL": score -= 20
       elif sev == "HIGH": score -= 10
       elif sev == "MEDIUM": score -= 5
       else: score -= 2
   score = max(0, min(100, score))
   trust_scores[playfab_id] = score
   return score

def add_violation(playfab_id, violation_type, reason, severity="MEDIUM", details=None):
   if severity not in VALID_SEVERITIES:
       print(f"[add_violation] invalid severity {severity!r}, defaulting to MEDIUM")
       severity = "MEDIUM"
   if violation_type not in VALID_VIOLATION_TYPES:
       print(f"[add_violation] unrecognized violation_type {violation_type!r} (recording anyway)")

   violation = {
       "type": violation_type, "reason": reason, "severity": severity,
       "timestamp": datetime.now().isoformat(), "details": details
   }
   if playfab_id:
       violation_cache[playfab_id].append(violation)
       col = _get_violation_col()
       if col is not None:
           try:
               col.update_one(
                   {"playFabId": playfab_id},
                   {"$push": {"violations": violation},
                    "$setOnInsert": {"playFabId": playfab_id}},
                   upsert=True
               )
           except Exception as e:
               print(f"[add_violation] Mongo persist failed for {playfab_id}: {e}")
       if violation_type in CHEAT_BLOCK_TYPES:
           trust_scores[playfab_id] = 0
       else:
           trust_scores[playfab_id] = calculate_trust_score(playfab_id)
       if violation_type in CHEAT_BLOCK_TYPES:
           send_cheat_detected_alert(playfab_id, violation_type, reason, severity)
           add_permanent_block(playfab_id, reason, violation_type)
           ingame_name = get_ingame_name(playfab_id)
           send_alert(f"Auth Block Applied: {violation_type}", [
               {"name": "PlayFab ID", "value": playfab_id, "inline": True},
               {"name": "In-Game Name", "value": ingame_name, "inline": True},
               {"name": "Reason", "value": reason, "inline": False},
               {"name": "Severity", "value": severity, "inline": True},
               {"name": "Trust Score", "value": "0", "inline": True},
               {"name": "Note", "value": "Player blocked from authenticating. PlayFab account untouched.", "inline": False}
           ], 0x8B0000)
       elif violation_type in ["NONCE_VERIFICATION_FAILED", "HEARTBEAT_LOST"]:
           send_alert(f"Violation: {violation_type}", [
               {"name": "PlayFab ID", "value": playfab_id or "Unknown", "inline": True},
               {"name": "Reason", "value": reason, "inline": False},
               {"name": "Severity", "value": severity, "inline": True},
               {"name": "Trust Score", "value": str(trust_scores.get(playfab_id, 100)), "inline": True}
           ], 0xFF6600)
   return violation

def _has_active_session_for_oculus(oculus_id):
   for pid, sess in active_sessions.items():
       if str(sess.get("oculus_id")) == str(oculus_id):
           return True
   return False

def is_heartbeat_valid(oculus_id, playfab_id=None, client_ip=None, allow_new_session=True):
   if not oculus_id:
       print("[HB] FAIL-CLOSED: oculus_id is null/empty - rejecting heartbeat check")
       return False, "missing_oculus_id"
   if oculus_id in HB_BYPASS_WHITELIST_OCULUS:
       print(f"[HB] OculusId {oculus_id} in heartbeat bypass whitelist - allowing")
       return True, None
   if client_ip and client_ip in HB_BYPASS_WHITELIST_IPS:
       print(f"[HB] IP {client_ip} in heartbeat bypass whitelist - allowing")
       return True, None
   if _get_hb_col() is None:
       if FAIL_CLOSED:
           return False, "Heartbeat database unreachable (fail-closed)"
       return True, None
   hb_doc = hb_read(oculus_id)
   last_hb = hb_doc.get("last_heartbeat", 0)
   sess = _load_hb_session(oculus_id)
   if not sess and last_hb == 0:
       return True, None
   auth_time = sess.get("auth_time", 0) if sess else 0
   if auth_time and (time.time() - auth_time) < 30:
       return True, None
   if last_hb > 0 and (time.time() - last_hb) <= HEARTBEAT_GRACE_PERIOD:
       return True, None
   return False, f"No valid heartbeat for OculusId {oculus_id}"

def photon_beat_status(oculus_id, playfab_id=None):
   if not PHOTON_REQUIRE_BEAT:
       return "ok", "disabled"
   if not oculus_id:
       print("[Photon] FAIL-CLOSED: oculus_id is null/empty - treating as stale")
       return "stale", "missing_oculus_id"
   if oculus_id in HB_BYPASS_WHITELIST_OCULUS:
       return "ok", "whitelisted_oculus"
   if playfab_id:
       client_ip = (active_sessions.get(playfab_id, {}).get("ip")
                    or playfabCache.get(playfab_id, {}).get("ip"))
       if client_ip and client_ip in HB_BYPASS_WHITELIST_IPS:
           return "ok", "whitelisted_ip"
   hb_doc = hb_read(oculus_id)
   last_hb = hb_doc.get("last_heartbeat", 0)
   if last_hb == 0:
       return "not_ready", "no_heartbeat_ever"
   if (time.time() - last_hb) <= HEARTBEAT_GRACE_PERIOD:
       # If there is a block, auto-unblock
       if playfab_id and playfab_id in blocked_playfab_ids:
           blocked_info = blocked_playfab_ids[playfab_id]
           if blocked_info.get("type") == "HEARTBEAT_FAILED":
               _ub_col = _get_blocked_col()
               if _ub_col is not None:
                   _ub_doc = _ub_col.find_one({"playFabId": playfab_id})
                   if _ub_doc and _ub_doc.get("unblock_beats", 0) >= 1:
                       remove_permanent_block(playfab_id)
                       blocked_playfab_ids.pop(playfab_id, None)
                       send_alert("Player Auto-Unblocked (1 Valid Heartbeat)", [
                           {"name": "PlayFab ID", "value": f"```{playfab_id}```", "inline": True},
                           {"name": "Oculus ID", "value": f"```{oculus_id}```", "inline": True},
                           {"name": "Status", "value": "```UNBLOCKED - heartbeat lib confirmed running```", "inline": False}
                       ], 0x00FF00)
                   elif _ub_doc is None:
                       blocked_playfab_ids.pop(playfab_id, None)
       return "ok", "fresh_beat"
   return "stale", f"beat_age_{int(time.time() - last_hb)}s"

def _playfab_id_from_oculus(oculus_id):
   for pid, sess in active_sessions.items():
       if str(sess.get("oculus_id")) == str(oculus_id):
           return pid
   for pid, cache in playfabCache.items():
       if str(cache.get("OculusId")) == str(oculus_id):
           return pid
   return None

# ========== ENHANCED PCVR DETECTION ==========
def _is_quest_device(device_model):
   if not device_model:
       return False
   dm_lower = device_model.lower().strip()
   for q in QUEST_DEVICE_ALLOWLIST:
       if q in dm_lower:
           return True
   return False

def detect_pcvr(playfab_id, platform, device_model, user_agent):
   if not ENFORCE_PCVR_BAN:
       return False
   platform_s  = (platform or "").lower().strip()
   device_s    = (device_model or "").lower().strip()
   ua_s        = (user_agent or "").lower().strip()
   reasons     = []

   if not platform_s or not device_s:
       reasons.append(f"Missing platform/device (platform={platform!r}, device={device_model!r})")
   for kw in PCVR_PLATFORM_KEYWORDS:
       if kw in platform_s:
           reasons.append(f"Platform keyword '{kw}' in '{platform}'")
           break
   for kw in PCVR_DEVICE_KEYWORDS:
       if kw in device_s:
           reasons.append(f"Device keyword '{kw}' in '{device_model}'")
           break
   for kw in PCVR_UA_KEYWORDS:
       if kw in ua_s:
           reasons.append(f"UA keyword '{kw}' in User-Agent")
           break
   if device_s and not _is_quest_device(device_model):
       reasons.append(f"Device '{device_model}' not in Quest allowlist")
   if platform_s and platform_s not in ("quest", "android", "androidplayer", "quest 2",
                                         "quest 3", "quest 3s", "quest pro", "meta quest"):
       reasons.append(f"Platform '{platform}' is not Quest/Android")

   if not reasons:
       return False

   reason_str = "; ".join(reasons)
   print(f"[PCVR] BLOCKED playfab={playfab_id}: {reason_str}")
   add_violation(
       playfab_id, "PCVR_DETECTED",
       f"PCVR detected - {reason_str}",
       "CRITICAL",
       {"platform": platform, "deviceModel": device_model, "userAgent": user_agent[:200]}
   )
   return True

def verify_meta_token_via_graph(token):
   try:
       url = "https://graph.oculus.com/platform_integrity/verify"
       params = {"token": token, "access_token": META_ATTEST_CREDS}
       response = requests.get(url, params=params, timeout=10)
       body = response.json()

       # Auth / request-level failure (e.g. bad access_token) surfaces as top-level "error".
       if isinstance(body, dict) and "error" in body:
           return None, f"Meta Graph Error: {body['error'].get('message')}"

       # The verify endpoint WRAPS the result:
       #   {"data":[{"message":"success","claims":"<base64url_json>"}]}
       # The real claims are Base64URL-encoded inside data[0].claims - they are NOT
       # top-level on the response. Unwrap + decode before reading any field.
       entries = body.get("data") if isinstance(body, dict) else None
       if not entries or not isinstance(entries, list):
           return None, f"Unexpected verify response: {str(body)[:160]}"
       entry = entries[0] or {}
       message = str(entry.get("message", "")).lower()
       if message != "success":
           # e.g. "invalid signature", "token expired"
           return None, f"Attestation rejected: {entry.get('message')}"

       claim_b64 = entry.get("claims", "")
       if not claim_b64:
           return None, "Verify response missing claims"
       pad = "=" * (-len(claim_b64) % 4)   # restore Base64 padding
       try:
           claims = json.loads(base64.urlsafe_b64decode(claim_b64 + pad).decode("utf-8"))
       except Exception as e:
           return None, f"Claims decode error: {e}"

       app_state = claims.get("app_state", {}) or {}

       # Meta's field for the manifest applicationId is "package_id" (com.example.name123),
       # nested under app_state.
       pkg = app_state.get("package_id")
       if pkg != EXPECTED_PACKAGE_NAME:
           return None, f"Package Name Mismatch: got {pkg}"

       # package_cert_sha256_digest is a LIST of lowercase-hex digests (no colons),
       # under app_state. Match the expected cert against ANY digest in the chain.
       if EXPECTED_APK_SIGNATURE:
           expected_norm = EXPECTED_APK_SIGNATURE.replace(":", "").lower()
           digests = app_state.get("package_cert_sha256_digest", []) or []
           if isinstance(digests, str):
               digests = [digests]
           actual_norms = [str(d).replace(":", "").lower() for d in digests]
           if expected_norm and actual_norms and expected_norm not in actual_norms:
               return None, f"APK Certificate Mismatch: got {','.join(actual_norms)}"

       return claims, None
   except Exception as e:
       return None, f"Graph Connection Error: {str(e)}"

def meta_device_ban(unique_id=None, ban_id=None, is_banned=True, remaining_minutes=None):
   if not settings.EnableMetaDeviceBan:
       return None
   if not unique_id and not ban_id:
       return None
   if remaining_minutes is None:
       remaining_minutes = settings.DefaultDeviceBanMinutes
   params = {
       "method": "POST",
       "is_banned": str(bool(is_banned)).lower(),
       "access_token": settings.AppCreds
   }
   if is_banned:
       params["remaining_time_in_minute"] = remaining_minutes
   if ban_id:
       params["ban_id"] = ban_id
   else:
       params["unique_id"] = unique_id
   try:
       resp = requests.post(url="https://graph.oculus.com/platform_integrity/device_ban", params=params, timeout=5)
       result = resp.json()
       if "error" in result:
           print(f"[DeviceBan] Error: {result['error'].get('message')}")
           return None
       return result
   except Exception as e:
       print(f"[DeviceBan] Exception: {e}")
       return None

def get_cached_unique_id(playfab_id):
   return (active_sessions.get(playfab_id, {}).get("meta_unique_id")
           or playfabCache.get(playfab_id, {}).get("MetaDeviceUniqueId"))

def get_cached_ban_id(playfab_id):
   return playfabCache.get(playfab_id, {}).get("MetaDeviceBanId")

def ban_player_device(playfab_id, reason):
   unique_id = get_cached_unique_id(playfab_id)
   if not unique_id:
       print(f"[DeviceBan] No cached unique_id for {playfab_id}, cannot device-ban.")
       return None
   result = meta_device_ban(unique_id=unique_id, is_banned=True, remaining_minutes=settings.DefaultDeviceBanMinutes)
   if result and result.get("ban_id"):
       playfabCache.setdefault(playfab_id, {})["MetaDeviceBanId"] = result["ban_id"]
       send_alert("Meta Device Banned (Permanent Ban)", [
           {"name": "PlayFab ID", "value": f"```{playfab_id}```", "inline": True},
           {"name": "Unique ID", "value": f"```{unique_id}```", "inline": True},
           {"name": "Ban ID", "value": f"```{result['ban_id']}```", "inline": True},
           {"name": "Reason", "value": f"```{reason}```", "inline": False},
       ], 0x8B0000)
   return result

def unban_player_device(playfab_id, note="Manually unbanned by admin"):
   ban_id = get_cached_ban_id(playfab_id)
   unique_id = get_cached_unique_id(playfab_id)
   if not ban_id and not unique_id:
       return None
   result = meta_device_ban(unique_id=unique_id if not ban_id else None, ban_id=ban_id, is_banned=False)
   if result is not None:
       playfabCache.setdefault(playfab_id, {}).pop("MetaDeviceBanId", None)
       send_alert("Meta Device Ban Reversed", [
           {"name": "PlayFab ID", "value": f"```{playfab_id}```", "inline": True},
           {"name": "Ban ID Used", "value": f"```{ban_id or 'N/A'}```", "inline": True},
           {"name": "Unique ID Used", "value": f"```{unique_id or 'N/A'}```", "inline": True},
           {"name": "Note", "value": f"```{note}```", "inline": False},
       ], 0x00FF00)
   return result

def auto_ban_user(playfab_id, reason):
   if not playfab_id:
       return False
   ingame_name = get_ingame_name(playfab_id)
   is_permanent = True
   ban_request = requests.post(
       url=f"https://{settings.TitleId}.playfabapi.com/Admin/BanUsers",
       json={"Bans": [{"PlayFabId": playfab_id, "DurationInHours": 0, "Reason": reason}]},
       headers=settings.GetAuthHeaders()
   )
   if ban_request.status_code == 200:
       device_ban_result = ban_player_device(playfab_id, reason) if is_permanent else None
       cached_hwid = (active_sessions.get(playfab_id, {}).get("hwid")
                      or playfabCache.get(playfab_id, {}).get("HWID"))
       if settings.EnableHWIDBan and cached_hwid and cached_hwid != "NOT_SENT":
           banned_hwids.add(cached_hwid)
       send_alert("Auto-Ban Executed", [
           {"name": "PlayFab ID", "value": playfab_id, "inline": True},
           {"name": "In-Game Name", "value": ingame_name, "inline": True},
           {"name": "Meta Device Ban ID", "value": f"```{device_ban_result['ban_id'] if device_ban_result else 'N/A'}```", "inline": True},
           {"name": "HWID Banned (fallback)", "value": f"```{cached_hwid or 'N/A'}```", "inline": True},
           {"name": "Reason", "value": reason, "inline": False}
       ], 0x8B0000)
       return True
   return False

def check_vpn(ip_address):
   if not settings.EnableVPNCheck:
       return False
   if not ip_address:
       print("[VPN] FAIL-CLOSED: ip_address is null/empty - treating as VPN/proxy")
       return True
   try:
       response = requests.get(
           f"http://ip-api.com/json/{ip_address}?fields=status,proxy,hosting", timeout=3
       )
       if response.status_code == 200:
           data = response.json()
           return data.get("proxy", False) or data.get("hosting", False)
   except:
       pass
   return False

def detect_speed_hack(playfab_id, current_position, current_time):
   if not settings.EnableSpeedDetection:
       return False
   if not playfab_id or not current_position:
       print(f"[SpeedHack] FAIL-CLOSED: playfab_id={playfab_id} position={current_position} - treating as violation")
       return True
   cache = movement_cache[playfab_id]
   if cache["lastPosition"] is not None and cache["lastTime"] is not None:
       delta_time = current_time - cache["lastTime"]
       if delta_time > 0:
           dx = current_position.get("x", 0) - cache["lastPosition"].get("x", 0)
           dy = current_position.get("y", 0) - cache["lastPosition"].get("y", 0)
           dz = current_position.get("z", 0) - cache["lastPosition"].get("z", 0)
           distance = (dx*dx + dy*dy + dz*dz) ** 0.5
           speed = distance / delta_time
           cache["speeds"].append(speed)
           if len(cache["speeds"]) > 10:
               cache["speeds"].pop(0)
           if speed > settings.MaxAllowedSpeed:
               cache["speeds"] = cache["speeds"][-5:]
               avg_speed = sum(cache["speeds"]) / len(cache["speeds"]) if cache["speeds"] else speed
               if avg_speed > settings.MaxAllowedSpeed:
                   add_violation(playfab_id, "SPEED_HACK",
                       f"Speed hack detected: {avg_speed:.2f} units/sec (max: {settings.MaxAllowedSpeed})",
                       "HIGH", {"speed": avg_speed})
                   return True
   cache["lastPosition"] = current_position
   cache["lastTime"] = current_time
   return False

def detect_long_arms(playfab_id, arm_length):
   if not settings.EnableArmLengthDetection:
       return False
   if not playfab_id or arm_length is None:
       print(f"[LongArms] FAIL-CLOSED: playfab_id={playfab_id} arm_length={arm_length} - treating as violation")
       return True
   cache = movement_cache[playfab_id]
   cache["armLengths"].append(arm_length)
   if len(cache["armLengths"]) > 10:
       cache["armLengths"].pop(0)
   if arm_length > settings.MaxAllowedArmLength:
       avg_arm_length = sum(cache["armLengths"]) / len(cache["armLengths"]) if cache["armLengths"] else arm_length
       if avg_arm_length > settings.MaxAllowedArmLength:
           add_violation(playfab_id, "LONG_ARMS",
               f"Long arms detected: {avg_arm_length:.2f} units (max: {settings.MaxAllowedArmLength})",
               "MEDIUM", {"armLength": avg_arm_length})
           return True
   return False

def generate_session_token(playfab_id):
   timestamp = str(int(time.time()))
   random_part = str(random.randint(100000, 999999))
   data = f"{playfab_id}|{timestamp}|{random_part}"
   signature = hmac.new(settings.SecretKey.encode(), data.encode(), hashlib.sha256).hexdigest()
   return f"{data}|{signature}"

def verify_session_token(token):
   if not token:
       return None
   try:
       parts = token.split("|")
       if len(parts) != 4:
           return None
       playfab_id, timestamp, random_part, signature = parts
       data = f"{playfab_id}|{timestamp}|{random_part}"
       expected = hmac.new(settings.SecretKey.encode(), data.encode(), hashlib.sha256).hexdigest()
       if hmac.compare_digest(signature, expected):
           if int(timestamp) > int(time.time()) - 86400:
               return playfab_id
   except:
       pass
   return None

def ValidateOculusAccount(Nonce, OculusId, ClientCustomId):
   if not Nonce or not OculusId or not ClientCustomId:
       missing = []
       if not Nonce: missing.append("Nonce")
       if not OculusId: missing.append("OculusId")
       if not ClientCustomId: missing.append("ClientCustomId")
       return (False, None, None, f"Missing required fields: {', '.join(missing)}")
   VerifyNonceReq = requests.post(
       url="https://graph.oculus.com/user_nonce_validate",
       json={"access_token": settings.AppCreds, "nonce": Nonce, "user_id": OculusId},
       headers={"Content-Type": "application/json"}
   )
   nonce_resp = VerifyNonceReq.json()
   print(json.dumps(nonce_resp, indent=2))
   if not nonce_resp.get("is_valid"):
       return (False, None, None, "Nonce validation failed")
   OculusDataReq = requests.get(
       url=f"https://graph.oculus.com/{OculusId}?access_token={settings.AppCreds}&fields=org_scoped_id,alias",
       headers={"Content-Type": "application/json"}
   )
   print(json.dumps(OculusDataReq.json(), indent=2))
   if OculusDataReq.status_code != 200:
       return (False, None, None, "Failed to retrieve Oculus data")
   OculusData = OculusDataReq.json()
   OrgScope = OculusData.get("org_scoped_id")
   Alias = OculusData.get("alias")
   if not OrgScope:
       return (False, None, None, "Missing org_scoped_id")
   if not Alias:
       return (False, None, None, "Missing alias")
   ServerCustomId = f"OCULUS{OrgScope}"
   if ClientCustomId.startswith("OCULUS"):
       ClientOrgScope = ClientCustomId[6:]
   elif ClientCustomId.startswith("OC"):
       ClientOrgScope = ClientCustomId[2:]
   else:
       return (False, None, None, "Invalid CustomId prefix")
   if ClientOrgScope != OrgScope:
       return (False, None, None, "CustomId mismatch")
   return (True, ServerCustomId, Alias, None)

def CheckUserEntitlement(OculusId):
   if not settings.EntitlementCheck:
       return (True, None, {"status": "skipped", "reason": "EntitlementCheck disabled"})
   if not OculusId:
       print("[Entitlement] FAIL-CLOSED: OculusId is null/empty")
       return (False, "OculusId is null - cannot verify entitlement", {"status": "fail_closed"})
   EntitlementReq = requests.post(
       url=f"https://graph.oculus.com/{settings.OculusAppId}/verify_entitlement",
       data={"access_token": settings.AppCreds, "user_id": str(OculusId)}
   )
   print(f"Entitlement check response: {EntitlementReq.status_code}")
   print(json.dumps(EntitlementReq.json(), indent=2))
   result = EntitlementReq.json()
   response_info = {"status_code": EntitlementReq.status_code, "response": result}
   if EntitlementReq.status_code != 200:
       return (False, "Failed to verify entitlement", response_info)
   if "error" in result or not result.get("success", False):
       return (False, "User does not own this application", response_info)
   return (True, None, response_info)

def run_reauth_pass():
   checked = 0
   dropped = 0
   try:
       for sess in _all_sessions():
           oculus_id = sess.get("oculusId")
           playfab_id = sess.get("playfabId")
           if not oculus_id:
               continue
           checked += 1
           hb_doc = hb_read(oculus_id)
           last_hb = hb_doc.get("last_heartbeat", 0)
           beat_stale = (last_hb == 0) or ((time.time() - last_hb) > HEARTBEAT_GRACE_PERIOD)
           auth_time = sess.get("auth_time", 0)
           in_grace = auth_time and (time.time() - auth_time) <= PHOTON_AUTH_GRACE and not sess.get("grace_used", False)
           if beat_stale and not in_grace:
               print(f"[ReAuth] Heartbeat stale for oculus {oculus_id} (pf {playfab_id}) - dropping session, no ban")
               _drop_session(oculus_id)
               active_sessions.pop(playfab_id, None)
               dropped += 1
               continue
           if playfab_id and is_playfab_blocked(playfab_id):
               binfo = blocked_playfab_ids[playfab_id]
               alias = playfabCache.get(playfab_id, {}).get("Alias", "N/A")
               ip = playfabCache.get(playfab_id, {}).get("ip", "N/A")
               ingame_name = get_ingame_name(playfab_id)
               send_webhook({
                   "title": "CHEAT DETECTED - Periodic Re-Auth Check",
                   "color": 0xFF0000,
                   "description": "Player caught during re-auth scan",
                   "fields": [
                       {"name": "PlayFab ID", "value": f"```{playfab_id}```", "inline": True},
                       {"name": "In-Game Name", "value": f"```{ingame_name}```", "inline": True},
                       {"name": "Meta Alias", "value": f"```{alias}```", "inline": True},
                       {"name": "Oculus ID", "value": f"```{oculus_id}```", "inline": True},
                       {"name": "IP Address", "value": f"```{ip}```", "inline": True},
                       {"name": "Cheat Type", "value": f"```{binfo['type']}```", "inline": True},
                       {"name": "Block Reason", "value": f"```{binfo['reason']}```", "inline": False},
                       {"name": "Blocked At", "value": f"```{binfo['timestamp']}```", "inline": True},
                       {"name": "Action", "value": "```Disconnected from Photon + PlayFab Banned```", "inline": False},
                   ],
                   "timestamp": datetime.now().isoformat(),
                   "footer": {"text": "Anti-Cheat - Periodic Re-Auth"}
               }, ALERT_WEBHOOK_URL)
               _drop_session(oculus_id)
               active_sessions.pop(playfab_id, None)
               dropped += 1
               continue
   except Exception as e:
       print(f"[ReAuth Pass Error] {e}")
   print(f"[ReAuth] swept {checked} sessions, dropped {dropped}")
   return checked

# ====================================================================
# FLASK ENDPOINTS
# ====================================================================

@app.route("/", methods=["POST", "GET"])
def main():
   return "XREAC'S BACKEND7y"

@app.route("/health", methods=["GET"])
def health():
   status = {"status": "healthy", "timestamp": datetime.now().isoformat()}
   if _MONGO_URI:
       status["mongodb"] = "connected" if _get_hb_col() is not None else "unreachable"
       if status["mongodb"] == "unreachable":
           status["status"] = "degraded"
   else:
       status["mongodb"] = "not_configured"
   http_code = 200 if status["status"] == "healthy" else 503
   return jsonify(status), http_code

@app.route("/api/cron/reauth", methods=["GET", "POST"])
@rate_limit(max_requests=5, window_seconds=60)
def cron_reauth():
   n = run_reauth_pass()
   return jsonify({"status": "ok", "sessionsChecked": n}), 200

# ---------- Attestation Endpoints ----------
@app.route("/api/AttestNonce", methods=["POST"])
@rate_limit(max_requests=20, window_seconds=60)
def attest_nonce():
   data = request.get_json() or {}
   oculus_id = data.get("oculusId") or data.get("playFabId", "N/A")
   playfab_id = data.get("playFabId", "N/A")
   if oculus_id and oculus_id != "N/A" and (not playfab_id or playfab_id == "N/A"):
       resolved = _oculus_for_playfab_reverse(oculus_id)
       if resolved:
           playfab_id = resolved
   random_bytes = os.urandom(16)
   challenge_nonce = base64.urlsafe_b64encode(random_bytes).decode().rstrip("=")
   _store_nonce(challenge_nonce, oculus_id, playfab_id)
   return jsonify({"challengeNonce": challenge_nonce}), 200

@app.route("/api/AttestVerify", methods=["POST"])
@rate_limit(max_requests=20, window_seconds=60)
def attest_verify():
   data = request.get_json() or {}
   attestation_token = data.get("token")
   oculus_id = data.get("oculusId")
   playfab_id = data.get("playFabId")
   client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
   if client_ip and "," in client_ip:
       client_ip = client_ip.split(",")[0].strip()
   if not attestation_token:
       return jsonify({"error": "Missing token"}), 400

   if oculus_id and not playfab_id:
       playfab_id = _oculus_for_playfab_reverse(oculus_id)
   if not oculus_id and playfab_id:
       oculus_id = _oculus_for_playfab(playfab_id)

   claims, error = verify_meta_token_via_graph(attestation_token)
   if not claims:
       send_alert("Attestation Verify Failed", [
           {"name": "Oculus ID", "value": str(oculus_id or "N/A"), "inline": True},
           {"name": "PlayFab ID", "value": str(playfab_id or "N/A"), "inline": True},
           {"name": "IP", "value": client_ip, "inline": True},
           {"name": "Error", "value": str(error)[:200], "inline": False},
       ], 0xFF6600)
       return jsonify({"verified": False, "reason": f"Meta verification failed: {error}"}), 403

   request_details = claims.get("request_details", {})
   nonce = request_details.get("nonce")
   timestamp = request_details.get("timestamp", 0)

   nonce_record = _pop_nonce(nonce)
   if not nonce_record:
       if playfab_id:
           add_violation(playfab_id, "MODDED_CLIENT", "Attestation nonce missing/unrecognized (possible replay)", "CRITICAL")
       return jsonify({"verified": False, "reason": "Unrecognized or reused nonce"}), 403

   if not oculus_id:
       oculus_id = nonce_record.get("oculusId")
   if not playfab_id or playfab_id == "N/A":
       playfab_id = nonce_record.get("playFabId")
   if playfab_id == "N/A":
       playfab_id = None

   if abs(time.time() - timestamp) > 300:
       return jsonify({"verified": False, "reason": "Stale attestation timestamp"}), 403

   device_state = claims.get("device_state", {})
   unique_id = device_state.get("unique_id")
   integrity_state = device_state.get("device_integrity_state")
   device_ban_info = claims.get("device_ban")
   # There is no "genuine_app_binary" field. Genuineness = the app was installed from
   # the Meta Horizon Store, i.e. app_state.app_integrity_state == "StoreRecognized".
   # (Sideloaded / dev builds return "NotRecognized" or "NotEvaluated".)
   app_integrity_state = (claims.get("app_state", {}) or {}).get("app_integrity_state")
   is_genuine = (app_integrity_state == "StoreRecognized")

   if playfab_id and unique_id:
       playfabCache.setdefault(playfab_id, {})["MetaDeviceUniqueId"] = unique_id
       if playfab_id in active_sessions:
           active_sessions[playfab_id]["meta_unique_id"] = unique_id

   if device_ban_info and device_ban_info.get("is_banned"):
       ingame_name = get_ingame_name(playfab_id) if playfab_id else "N/A"
       send_alert("Banned Device Attempted Auth", [
           {"name": "Oculus ID", "value": str(oculus_id or "N/A"), "inline": True},
           {"name": "PlayFab ID", "value": str(playfab_id or "N/A"), "inline": True},
           {"name": "In-Game Name", "value": ingame_name, "inline": True},
           {"name": "IP", "value": client_ip, "inline": True},
           {"name": "Unique ID", "value": f"```{unique_id}```", "inline": True},
           {"name": "Remaining Ban (min)", "value": str(device_ban_info.get("remaining_ban_time")), "inline": True},
       ], 0x8B0000)
       return jsonify({"verified": True, "deviceBanned": True}), 403

   if integrity_state == "NotTrusted":
       if playfab_id:
           add_violation(playfab_id, "MODDED_CLIENT", "Attestation device_integrity_state=NotTrusted", "CRITICAL")
       return jsonify({"verified": True, "trusted": False, "integrityState": integrity_state}), 403

   if not is_genuine:
       if playfab_id:
           add_violation(playfab_id, "MODDED_CLIENT", "App binary not genuine", "CRITICAL")
       return jsonify({"verified": True, "trusted": False, "integrityState": integrity_state, "genuineBinary": False}), 403

   resolved_oculus = (
       oculus_id
       or claims.get("user_id")
       or (device_state.get("user_id") if isinstance(device_state, dict) else None)
   )

   print(f"[Attest] SUCCESS OculusID={resolved_oculus} PlayFabID={playfab_id} IP={client_ip} integrity={integrity_state} genuine={is_genuine}")

   if resolved_oculus:
       store_attestation(resolved_oculus, playfab_id, integrity_state, unique_id=unique_id)
       print(f"[Attest] Stored attestation record for oculus {resolved_oculus}")
   else:
       print(f"[Attest] WARN: could not resolve oculus_id - attestation NOT stored")

   send_webhook({
       "title": "Meta Attestation Passed", "color": 0x00FF00,
       "fields": [
           {"name": "Oculus ID", "value": str(resolved_oculus or "N/A"), "inline": True},
           {"name": "PlayFab ID", "value": str(playfab_id or "N/A"), "inline": True},
           {"name": "Client IP", "value": client_ip, "inline": True},
           {"name": "Meta Integrity", "value": integrity_state, "inline": True},
           {"name": "Genuine Binary", "value": "YES" if is_genuine else "NO", "inline": True},
       ],
       "timestamp": datetime.now().isoformat(),
   }, ALERT_WEBHOOK_URL)
   return jsonify({"verified": True, "trusted": True, "integrityState": integrity_state, "genuineBinary": True}), 200

@app.route("/api/AttestFull", methods=["POST"])
@rate_limit(max_requests=20, window_seconds=60)
def attest_full():
   return attest_verify()

# ---------- Heartbeat Endpoint ----------

@app.route("/api/HbSecret", methods=["POST"])
def hb_secret_endpoint():
   data = request.get_json() or {}
   oculus_id = data.get("oculusId")
   client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
   if client_ip and "," in client_ip:
       client_ip = client_ip.split(",")[0].strip()
   if not oculus_id:
       return jsonify({"error": "missing_oculus_id"}), 400
   sess = _load_hb_session(oculus_id)
   if not sess:
       return jsonify({"error": "no_session"}), 403
   secret = sess.get("hb_secret", "")
   if not secret:
       return jsonify({"error": "no_secret"}), 403
   return Response(json.dumps({"secret": secret}, separators=(",", ":")), mimetype="application/json"), 200

@app.route("/api/Heartbeat", methods=["POST"])
@rate_limit(max_requests=120, window_seconds=60)
def heartbeat():
   data = request.get_json() or {}
   oculus_id = data.get("oculusId")
   count = data.get("heartbeat", 0)
   ip = request.headers.get("X-Forwarded-For", request.remote_addr)
   if ip and "," in ip:
       ip = ip.split(",")[0].strip()
   if not oculus_id:
       return jsonify({"status": "error", "reason": "missing_oculus_id"}), 400
   _hb_rl = getattr(heartbeat, '_rate', {})
   _now = time.time()
   _rl = _hb_rl.get(oculus_id, (0, _now))
   if _now - _rl[1] > 60:
       _hb_rl[oculus_id] = (1, _now)
   else:
       _hb_rl[oculus_id] = (_rl[0] + 1, _rl[1])
       if _rl[0] + 1 > 30:
           return jsonify({"status": "error", "reason": "rate_limited"}), 429
   heartbeat._rate = _hb_rl
   try:
       count = int(count)
   except (TypeError, ValueError):
       count = 0
   if ENFORCE_SIGNED_HEARTBEATS and oculus_id not in SIGNED_HB_WHITELIST_OCULUS and ip not in SIGNED_HB_WHITELIST_IPS:
       sig = data.get("sig", "")
       ts = data.get("ts", 0)
       _hb_sess = _load_hb_session(oculus_id)
       _in_bootstrap = not _hb_sess
       if _hb_sess:
           _auth_age = time.time() - _hb_sess.get("auth_time", 0)
           if _auth_age < 60:
               _in_bootstrap = True
       if not sig or not ts:
           if _in_bootstrap:
               print(f"[HB] Bootstrap grace: allowing unsigned HB for {oculus_id} (no session or fresh auth)")
           else:
               send_alert("UNSIGNED HEARTBEAT - Signature Missing", [
                   {"name": "Oculus ID", "value": f"```{oculus_id}```", "inline": True},
                   {"name": "IP", "value": f"```{ip}```", "inline": True},
                   {"name": "Detail", "value": "```Heartbeat sent without sig/ts - old or modded lib```", "inline": False},
               ], 0xFF0000)
               return jsonify({"status": "error", "reason": "missing_signature"}), 403
       else:
           try:
               ts = int(ts)
           except (TypeError, ValueError):
               return jsonify({"status": "error", "reason": "invalid_timestamp"}), 403
           if abs(time.time() - ts) > 120:
               send_alert("UNSIGNED HEARTBEAT - Stale Timestamp", [
                   {"name": "Oculus ID", "value": f"```{oculus_id}```", "inline": True},
                   {"name": "IP", "value": f"```{ip}```", "inline": True},
                   {"name": "Timestamp Age", "value": f"```{abs(time.time() - ts):.0f}s```", "inline": True},
                   {"name": "Detail", "value": "```Heartbeat timestamp too old - possible replay attack```", "inline": False},
               ], 0xFF0000)
               return jsonify({"status": "error", "reason": "stale_heartbeat"}), 403
           _hb_sess_for_sig = _hb_sess or _load_hb_session(oculus_id)
           hb_secret = _hb_sess_for_sig.get("hb_secret", "") if _hb_sess_for_sig else ""
           expected_sig = hashlib.sha256(f"{oculus_id}:{count}:{ts}{hb_secret}".encode()).hexdigest()
           if sig != expected_sig:
               if _in_bootstrap:
                   print(f"[HB] Bootstrap grace: bad sig for {oculus_id} - allowing while client syncs secret")
               else:
                   send_alert("UNSIGNED HEARTBEAT - Invalid Signature", [
                       {"name": "Oculus ID", "value": f"```{oculus_id}```", "inline": True},
                       {"name": "IP", "value": f"```{ip}```", "inline": True},
                       {"name": "Detail", "value": "```Signature mismatch - forged or wrong secret```", "inline": False},
                   ], 0xFF0000)
                   return jsonify({"status": "error", "reason": "invalid_signature"}), 403
   _hb_not_ready_attempts.pop(oculus_id, None)

   sess_check = _load_hb_session(oculus_id)
   if sess_check:
       last_count = sess_check.get("last_count", -1)
       if last_count >= 0 and count < last_count and count != 0 and count != 1:
           playfab_id_hb = sess_check.get("playfabId")
           send_alert("HEARTBEAT COUNT ANOMALY - Possible Replay", [
               {"name": "Oculus ID", "value": f"```{oculus_id}```", "inline": True},
               {"name": "PlayFab ID", "value": f"```{playfab_id_hb or 'N/A'}```", "inline": True},
               {"name": "IP", "value": f"```{ip}```", "inline": True},
               {"name": "Last Count", "value": f"```{last_count}```", "inline": True},
               {"name": "Received Count", "value": f"```{count}```", "inline": True},
               {"name": "Detail", "value": "```Count went backward - possible replayed or spoofed heartbeat```", "inline": False},
           ], 0xFF6600)
           if playfab_id_hb:
               add_violation(playfab_id_hb, "HEARTBEAT_FAILED",
                             f"Heartbeat count went backward: {last_count} -> {count}", "HIGH")
       elif last_count >= 0 and count == last_count and count > 1:
           pass

   # Auto-unblock logic (1 valid beat, no minimum age)
   _unblock_col = _get_blocked_col()
   if _unblock_col is not None:
       _block_doc = _unblock_col.find_one({"oculusId": str(oculus_id), "type": "HEARTBEAT_FAILED"})
       if not _block_doc:
           _ub_sess = _load_hb_session(oculus_id)
           if _ub_sess and _ub_sess.get("playfabId"):
               _block_doc = _unblock_col.find_one({"playFabId": _ub_sess["playfabId"], "type": "HEARTBEAT_FAILED"})
       if not _block_doc:
           for _bd in _unblock_col.find({"type": "HEARTBEAT_FAILED"}):
               if str(_bd.get("oculusId")) == str(oculus_id):
                   _block_doc = _bd
                   break

       if _block_doc:
           _ub_pid = _block_doc.get("playFabId", "N/A")
           _ub_beats = _block_doc.get("unblock_beats", 0) + 1

           if _ub_beats >= 1:   # No age check - unblock on first valid beat
               remove_permanent_block(_ub_pid)
               blocked_playfab_ids.pop(_ub_pid, None)
               send_alert("Player Auto-Unblocked (1 Valid Heartbeat)", [
                   {"name": "PlayFab ID", "value": f"```{_ub_pid}```", "inline": True},
                   {"name": "Oculus ID", "value": f"```{oculus_id}```", "inline": True},
                   {"name": "IP", "value": f"```{ip}```", "inline": True},
                   {"name": "Heartbeats", "value": f"```{_ub_beats}/1```", "inline": True},
                   {"name": "Status", "value": "```UNBLOCKED - heartbeat lib confirmed running```", "inline": False}
               ], 0x00FF00)
               print(f"[Heartbeat] Auto-unblocked {_ub_pid} after {_ub_beats} valid heartbeats")
           else:
               try:
                   _unblock_col.update_one(
                       {"playFabId": _ub_pid},
                       {"$set": {"unblock_beats": _ub_beats}}
                   )
               except Exception as e:
                   print(f"[Heartbeat] Failed to update unblock_beats: {e}")
               print(f"[Heartbeat] Block holding for {_ub_pid} - {_ub_beats}/1 heartbeats received")

   # Also check in-memory blocks
   for _pid, _binfo in list(blocked_playfab_ids.items()):
       if _binfo.get("type") != "HEARTBEAT_FAILED":
           continue
       stored_oid = str(_binfo.get("oculusId", ""))
       cached_oid = str(playfabCache.get(_pid, {}).get("OculusId", ""))
       if stored_oid == str(oculus_id) or cached_oid == str(oculus_id):
           if _unblock_col is not None:
               _mem_doc = _unblock_col.find_one({"playFabId": _pid})
               if not _mem_doc:
                   blocked_playfab_ids.pop(_pid, None)
           break

   hb_write(oculus_id, count, ip)
   _bump_hb_count(oculus_id, count)
   sess_for_secret = _load_hb_session(oculus_id)
   hb_sec = sess_for_secret.get("hb_secret", "") if sess_for_secret else ""
   return Response(json.dumps({"status":"ok","mode":"presence","s":hb_sec}, separators=(",",":")), mimetype="application/json"), 200

@app.route("/api/GameConfig", methods=["POST"])
@rate_limit(max_requests=30, window_seconds=60)
def game_config():
   data = request.get_json() or {}
   oculus_id = data.get("oculusId")
   ip = request.headers.get("X-Forwarded-For", request.remote_addr)
   if ip and "," in ip:
       ip = ip.split(",")[0].strip()
   if not oculus_id:
       return jsonify({"error": "missing_oculus_id"}), 400

   whitelisted = (oculus_id in SIGNED_HB_WHITELIST_OCULUS or ip in SIGNED_HB_WHITELIST_IPS)
   if not whitelisted:
       sig = data.get("sig", "")
       ts = data.get("ts", 0)
       count = data.get("heartbeat", 0)
       try:
           ts = int(ts); count = int(count)
       except (TypeError, ValueError):
           return jsonify({"error": "bad_request"}), 400
       if not sig or not ts:
           return jsonify({"error": "missing_signature"}), 403
       if abs(time.time() - ts) > 120:
           return jsonify({"error": "stale_request"}), 403
       sess = _load_hb_session(oculus_id)
       hb_secret = sess.get("hb_secret", "") if sess else ""
       if not hb_secret:
           return jsonify({"error": "no_session"}), 403
       expected_sig = hashlib.sha256(f"{oculus_id}:{count}:{ts}{hb_secret}".encode()).hexdigest()
       if sig != expected_sig:
           return jsonify({"error": "invalid_signature"}), 403

   payload = {
       "tid": settings.TitleId,
       "pun": settings.PhotonRealtimeAppId,
       "vox": settings.PhotonVoiceAppId,
   }
   return Response(json.dumps(payload, separators=(",", ":")), mimetype="application/json"), 200

@app.route("/api/ConfigCheck", methods=["POST"])
@rate_limit(max_requests=30, window_seconds=60)
def config_check():
   data = request.get_json() or {}
   oculus_id = data.get("oculusId")
   ip = request.headers.get("X-Forwarded-For", request.remote_addr)
   if ip and "," in ip:
       ip = ip.split(",")[0].strip()
   if not oculus_id:
       return jsonify({"error": "missing_oculus_id"}), 400

   if not settings.EnforceConfigMatch:
       return jsonify({"match": True, "enforced": False}), 200

   whitelisted = (oculus_id in SIGNED_HB_WHITELIST_OCULUS or ip in SIGNED_HB_WHITELIST_IPS)
   if not whitelisted:
       sig = data.get("sig", "")
       ts = data.get("ts", 0)
       count = data.get("heartbeat", 0)
       try:
           ts = int(ts); count = int(count)
       except (TypeError, ValueError):
           return jsonify({"error": "bad_request"}), 400
       if not sig or not ts:
           return jsonify({"error": "missing_signature"}), 403
       if abs(time.time() - ts) > 120:
           return jsonify({"error": "stale_request"}), 403
       sess = _load_hb_session(oculus_id)
       hb_secret = sess.get("hb_secret", "") if sess else ""
       if not hb_secret:
           return jsonify({"error": "no_session"}), 403
       expected_sig = hashlib.sha256(f"{oculus_id}:{count}:{ts}{hb_secret}".encode()).hexdigest()
       if sig != expected_sig:
           return jsonify({"error": "invalid_signature"}), 403

   tid = str(data.get("tid", ""))
   pun = str(data.get("pun", ""))
   vox = str(data.get("vox", ""))
   mism = []
   if tid != settings.TitleId:
       mism.append("tid")
   if pun != settings.PhotonRealtimeAppId:
       mism.append("pun")
   if vox != settings.PhotonVoiceAppId:
       mism.append("vox")

   if mism:
       playfab_id = _playfab_id_from_oculus(oculus_id)
       if playfab_id:
           add_violation(playfab_id, "MODDED_CLIENT",
                         f"Config mismatch: {','.join(mism)}", "CRITICAL")
           add_permanent_block(playfab_id,
                               f"Config mismatch: {','.join(mism)}",
                               "MODDED_CLIENT", oculus_id=oculus_id)
           send_alert("Config Mismatch - Permanent Block", [
               {"name": "PlayFab ID", "value": f"```{playfab_id}```", "inline": True},
               {"name": "Oculus ID", "value": f"```{oculus_id}```", "inline": True},
               {"name": "IP", "value": f"```{ip}```", "inline": True},
               {"name": "Mismatch", "value": f"```{','.join(mism)}```", "inline": False},
           ], 0xFF0000)
       else:
           add_violation(oculus_id, "MODDED_CLIENT",
                         f"Config mismatch: {','.join(mism)}", "CRITICAL")
           send_alert("Config Mismatch (unresolved OculusId)", [
               {"name": "Oculus ID", "value": f"```{oculus_id}```", "inline": True},
               {"name": "IP", "value": f"```{ip}```", "inline": True},
               {"name": "Mismatch", "value": f"```{','.join(mism)}```", "inline": False},
           ], 0xFF6600)
       return jsonify({"match": False, "enforced": True, "mismatch": mism}), 403
   return jsonify({"match": True, "enforced": True}), 200

@app.route("/api/HeartbeatViolation", methods=["POST"])
@rate_limit(max_requests=10, window_seconds=60)
def heartbeat_violation():
   data = request.get_json() or {}
   oculus_id = data.get("oculusId")
   bad_lib = data.get("badLib", "unknown")
   client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
   if client_ip and "," in client_ip:
       client_ip = client_ip.split(",")[0].strip()
   if not oculus_id:
       return jsonify({"error": "Missing oculusId"}), 400
   playfab_id = _playfab_id_from_oculus(oculus_id)
   if not playfab_id:
       send_alert("Native Lib Violation (unresolved OculusId)", [
           {"name": "Oculus ID", "value": f"```{oculus_id}```", "inline": True},
           {"name": "Bad Lib", "value": f"```{bad_lib}```", "inline": True},
           {"name": "IP", "value": f"```{client_ip}```", "inline": True},
       ], 0xFF6600)
       return jsonify({"recorded": False, "reason": "OculusId not mapped to PlayFabId"}), 200
   add_violation(playfab_id, "MODDED_CLIENT", f"Unauthorized native lib detected: {bad_lib}", "CRITICAL")
   return jsonify({"recorded": True, "playFabId": playfab_id}), 200

# ---------- BadLibDebug ----------
_badlib_rate = {}
BADLIB_RATE_LIMIT = 5

@app.route("/api/BadLibDebug", methods=["POST"])
@rate_limit(max_requests=5, window_seconds=60)
def bad_lib_debug():
   rl_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
   if rl_ip and "," in rl_ip:
       rl_ip = rl_ip.split(",")[0].strip()
   now = time.time()
   rl = _badlib_rate.get(rl_ip, (0, now))
   if now - rl[1] > 60:
       _badlib_rate[rl_ip] = (1, now)
   else:
       _badlib_rate[rl_ip] = (rl[0] + 1, rl[1])
       if rl[0] + 1 > BADLIB_RATE_LIMIT:
           return jsonify({"ok": False, "reason": "rate_limited"}), 429
   data = request.get_json() or {}
   oculus_id = data.get("oculusId", "UNKNOWN")
   bad_lib = data.get("badLib", "unknown")
   client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
   if client_ip and "," in client_ip:
       client_ip = client_ip.split(",")[0].strip()
   if client_ip in banned_ips or client_ip in PERMA_BANNED_IPS:
       return jsonify({"ok": True}), 200
   if isinstance(bad_lib, str) and bad_lib.startswith("HASHCHANGE|"):
       parts = bad_lib.split("|")
       lib_name = parts[1] if len(parts) > 1 else "unknown"
       actual_hash = parts[2] if len(parts) > 2 else "unknown"
       expected_hash = parts[3] if len(parts) > 3 else "unknown"
       send_alert("SHA256 HASH CHANGE - Native Lib Modified", [
           {"name": "Renamed / Modified File", "value": f"```{lib_name}```", "inline": False},
           {"name": "Actual SHA256 (on device)", "value": f"```{actual_hash}```", "inline": False},
           {"name": "Expected SHA256", "value": f"```{expected_hash}```", "inline": False},
           {"name": "Oculus ID", "value": f"```{oculus_id}```", "inline": True},
           {"name": "IP", "value": f"```{client_ip}```", "inline": True},
           {"name": "Action", "value": "```Player kicked by native lib```", "inline": False},
       ], 0xFF0000)
       return jsonify({"ok": True, "type": "hashchange"}), 200
   if isinstance(bad_lib, str) and bad_lib.startswith("SIZECHANGE|"):
       parts = bad_lib.split("|")
       lib_name = parts[1] if len(parts) > 1 else "unknown"
       actual_size = parts[2] if len(parts) > 2 else "unknown"
       expected_size = parts[3] if len(parts) > 3 else "unknown"
       send_alert("SIZE CHANGE - Native Lib Modified", [
           {"name": "Renamed / Modified File", "value": f"```{lib_name}```", "inline": False},
           {"name": "Actual Size (on device)", "value": f"```{actual_size} bytes```", "inline": False},
           {"name": "Expected Size", "value": f"```{expected_size} bytes```", "inline": False},
           {"name": "Oculus ID", "value": f"```{oculus_id}```", "inline": True},
           {"name": "IP", "value": f"```{client_ip}```", "inline": True},
           {"name": "Action", "value": "```Player kicked by native lib```", "inline": False},
       ], 0xFF0000)
       return jsonify({"ok": True, "type": "sizechange"}), 200
   if isinstance(bad_lib, str) and bad_lib.startswith("ATTEST"):
       # Attestation signals are telemetry, NOT library detections. This endpoint
       # does not kick/ban; enforcement lives at the Photon/PlayFab attestation gate.
       send_alert("Attestation Telemetry (informational - no kick)", [
           {"name": "Signal", "value": f"```{bad_lib}```", "inline": False},
           {"name": "Oculus ID", "value": f"```{oculus_id}```", "inline": True},
           {"name": "IP", "value": f"```{client_ip}```", "inline": True},
       ], 0x3498DB)
       return jsonify({"ok": True, "type": "attest_telemetry"}), 200
   send_alert("DEBUG - Unwhitelisted Lib Detected (kick triggered)", [
       {"name": "Bad Lib", "value": f"```{bad_lib}```", "inline": False},
       {"name": "Oculus ID", "value": f"```{oculus_id}```", "inline": True},
       {"name": "IP", "value": f"```{client_ip}```", "inline": True},
   ], 0xFFA500)
   return jsonify({"ok": True}), 200

# ---------- PlayFab Authentication ----------
@app.route("/api/PlayFabAuthentication", methods=["POST", "GET"])
@rate_limit(max_requests=10, window_seconds=60)
def playfabauthentication():
   global valid_host
   request_host = request.headers.get("Host")
   if valid_host is None:
       valid_host = request_host
   if request_host != valid_host:
       return "", 404

   user_agent = request.headers.get("User-Agent", "")
   if "UnityPlayer" not in user_agent:
       client_ip_ua = request.headers.get("X-Forwarded-For", request.remote_addr)
       if client_ip_ua and "," in client_ip_ua:
           client_ip_ua = client_ip_ua.split(",")[0].strip()
       record_auth_failure(client_ip_ua, "BAD_USER_AGENT",
                           f"User-Agent did not contain 'UnityPlayer': {user_agent[:120]}")
       return Response(
           json.dumps({"BanMessage": "Unable To Validate User Agent Integrity.", "BanExpirationTime": "Indefinite"}),
           mimetype="application/json"
       ), 403

   try:
       rjson = request.get_json()
       print(json.dumps(rjson, indent=2))
   except Exception as e:
       return jsonify({"Message": "Request body is missing or cannot be parsed.", "Error": "BadRequestBadBody"}), 400

   if rjson is None:
       return jsonify({"Message": "Request body is missing or cannot be parsed.", "Error": "BadRequestBadBody"}), 400

   AppVersion = (rjson.get("AppVersion") or rjson.get("appVersion") or rjson.get("version") or "1.1.73")
   OculusId = rjson.get("OculusId")
   Nonce = rjson.get("Nonce")
   CustomId = rjson.get("CustomId")
   Platform = rjson.get("Platform")
   AppId = rjson.get("AppId")
   HWID = (rjson.get("HWID") or rjson.get("hwid") or rjson.get("HardwareId") or rjson.get("deviceId") or "NOT_SENT")

   _raw_device = (rjson.get("DeviceModel") or rjson.get("deviceModel") or rjson.get("Device"))
   if not _raw_device:
       _ua_match = re.search(r"UnityPlayer/[\d.]+ \([^)]+\)\s+(.+)", user_agent)
       _raw_device = _ua_match.group(1).strip() if _ua_match else None
   DeviceModel = _raw_device or "Quest (model unknown)"

   client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
   if client_ip and "," in client_ip:
       client_ip = client_ip.split(",")[0].strip()

   # Master whitelist
   _is_dev_whitelisted = (
       (OculusId and str(OculusId) in HB_BYPASS_WHITELIST_OCULUS)
       or client_ip in HB_BYPASS_WHITELIST_IPS
   )
   if _is_dev_whitelisted:
       bcol_wl = _get_blocked_col()
       if bcol_wl is not None:
           try:
               _wl_block = bcol_wl.find_one({"oculusId": str(OculusId)}) if OculusId else None
               if _wl_block:
                   remove_permanent_block(_wl_block["playFabId"])
                   blocked_playfab_ids.pop(_wl_block["playFabId"], None)
                   print(f"[Auth] Cleared block for whitelisted OculusId {OculusId}")
           except:
               pass

       print(f"[Auth] WHITELISTED: OculusId={OculusId} IP={client_ip} - skipping all enforcement")

       is_valid, server_custom_id, alias, error_reason = ValidateOculusAccount(
           Nonce=Nonce, OculusId=OculusId, ClientCustomId=CustomId
       )
       if not is_valid:
           return jsonify({"Message": f"Oculus validation failed: {error_reason}", "Error": "ForbiddenValidationFailed"}), 403

       custom_id = server_custom_id
       login_request = requests.post(
           url=f"https://{settings.TitleId}.playfabapi.com/Server/LoginWithServerCustomId",
           json={"ServerCustomId": custom_id, "CreateAccount": True},
           headers=settings.GetAuthHeaders()
       )
       if login_request.status_code != 200:
           error_info = login_request.json()
           return jsonify({"Error": "PlayFab Error", "Message": error_info.get("errorMessage", "Login failed")}), login_request.status_code

       data = login_request.json().get("data")
       playFabId = data.get("PlayFabId")
       sessionTicket = data.get("SessionTicket")
       entityToken = data.get("EntityToken").get("EntityToken")
       entityType = data.get("EntityToken").get("Entity").get("Type")
       entityId = data.get("EntityToken").get("Entity").get("Id")

       requests.post(
           url=f"https://{settings.TitleId}.playfabapi.com/Server/LinkServerCustomId",
           json={"ForceLink": True, "ServerCustomId": custom_id, "PlayFabId": playFabId},
           headers=settings.GetAuthHeaders()
       )

       acc_req = requests.post(
           url=f"https://{settings.TitleId}.playfabapi.com/Server/GetUserAccountInfo",
           json={"PlayFabId": playFabId}, headers=settings.GetAuthHeaders()
       )
       acc_data = acc_req.json()
       AccountCreationIsoTimestamp = acc_data.get("data", {}).get("UserInfo", {}).get("Created")

       playfabCache.setdefault(playFabId, {})
       playfabCache[playFabId]["CustomId"] = CustomId
       playfabCache[playFabId]["ServerCustomId"] = custom_id
       playfabCache[playFabId]["OculusId"] = OculusId
       playfabCache[playFabId]["Alias"] = alias
       playfabCache[playFabId]["ip"] = client_ip
       playfabCache[playFabId]["HWID"] = HWID

       active_sessions[playFabId] = {
           "oculus_id": OculusId, "alias": alias, "ip": client_ip,
           "hwid": HWID, "session_ticket": sessionTicket, "login_time": time.time()
       }

       if playFabId in blocked_playfab_ids:
           remove_permanent_block(playFabId)

       session_token = generate_session_token(playFabId)
       trust_score = 100
       trust_scores[playFabId] = 100
       hb_secret = issue_hb_secret(OculusId, playFabId, client_ip=client_ip)

       print(f"[Auth] WHITELISTED AUTH SUCCESS: {playFabId} ({alias})")
       return jsonify({
           "SessionTicket": sessionTicket, "EntityToken": entityToken,
           "PlayFabId": playFabId, "EntityId": entityId, "EntityType": entityType,
           "AccountCreationIsoTimestamp": AccountCreationIsoTimestamp,
           "SessionToken": session_token, "TrustScore": trust_score,
           "HeartbeatSecret": hb_secret
       }), 200

   # PCVR check before login
   if ENFORCE_PCVR_BAN:
       if detect_pcvr("PRE_LOGIN", Platform, DeviceModel, user_agent):
           send_alert("PCVR BLOCKED - Pre-Login", [
               {"name": "Oculus ID", "value": f"```{OculusId or 'N/A'}```", "inline": True},
               {"name": "IP", "value": f"```{client_ip}```", "inline": True},
               {"name": "Platform", "value": f"```{Platform or 'N/A'}```", "inline": True},
               {"name": "Device", "value": f"```{DeviceModel}```", "inline": True},
               {"name": "User-Agent", "value": f"```{user_agent[:150]}```", "inline": False},
           ], 0xFF0000)
           return jsonify({
               "Message": "PC VR is not supported. Quest headset required.",
               "Error": "PCVR_BLOCKED"
           }), 403

   # HWID enforcement
   if settings.EnableHWIDBan:
       if not HWID or HWID == "NOT_SENT":
           client_ip_hwid = request.headers.get("X-Forwarded-For", request.remote_addr)
           if client_ip_hwid and "," in client_ip_hwid:
               client_ip_hwid = client_ip_hwid.split(",")[0].strip()
           record_auth_failure(
               client_ip_hwid,
               "MISSING_HWID",
               "HWID was null or NOT_SENT",
               oculus_id=str(OculusId or "N/A"),
               hwid="MISSING"
           )
           return jsonify({
               "Message": "Failed To Validate Device Identity.",
               "Error": "MISSING_HWID"
           }), 403

   device_id = HWID if (HWID and HWID != "NOT_SENT") else (CustomId or (str(OculusId) if OculusId else None))
   if not device_id:
       client_ip_dev = request.headers.get("X-Forwarded-For", request.remote_addr)
       if client_ip_dev and "," in client_ip_dev:
           client_ip_dev = client_ip_dev.split(",")[0].strip()
       record_auth_failure(client_ip_dev, "MISSING_DEVICE_ID",
                           "Could not determine any device identifier - fail-closed",
                           oculus_id=str(OculusId or "N/A"), hwid="MISSING")
       return jsonify({"Message": "Failed To Validate Device Identity.", "Error": "MISSING_DEVICE_ID"}), 403
   if is_device_banned(str(device_id)):
       send_alert("DEVICE BANNED - Auth Denied", [
           {"name": "Device ID", "value": f"```{device_id}```", "inline": True},
           {"name": "IP", "value": f"```{request.remote_addr}```", "inline": True},
       ], 0x8B0000)
       return jsonify({"Message": "Device is banned.", "Error": "DEVICE_BANNED"}), 403

   if check_vpn(client_ip):
       send_alert("VPN/Proxy Detected", [
           {"name": "IP", "value": client_ip, "inline": True},
           {"name": "Oculus ID", "value": OculusId or "N/A", "inline": True}
       ], 0xFF6600)
       return jsonify({"Message": "VPN/Proxy not allowed", "Error": "VPN_PROXY_DETECTED"}), 403

   if settings.EnableHWIDBan and HWID and HWID != "NOT_SENT" and (HWID in banned_hwids or HWID in PERMA_BANNED_HWIDS):
       send_alert("HWID Banned Attempt", [
           {"name": "HWID", "value": HWID, "inline": True},
           {"name": "IP", "value": client_ip, "inline": True}
       ], 0x8B0000)
       return jsonify({"Message": "This device is banned", "Error": "HWID_BANNED"}), 403

   if client_ip in banned_ips or client_ip in PERMA_BANNED_IPS:
       return jsonify({"Message": "IP is banned", "Error": "IP_BANNED"}), 403

   # Check MongoDB for blocks
   _mongo_block = None
   _is_auth_whitelisted = (
       (OculusId and str(OculusId) in HB_BYPASS_WHITELIST_OCULUS)
       or client_ip in HB_BYPASS_WHITELIST_IPS
   )
   if OculusId and not _is_auth_whitelisted:
       bcol = _get_blocked_col()
       if bcol is not None:
           _mongo_block = bcol.find_one({"oculusId": str(OculusId)})
           if _mongo_block and not _is_block_expired(_mongo_block):
               blocked_playfab_ids[_mongo_block["playFabId"]] = {
                   "reason": _mongo_block["reason"], "type": _mongo_block["type"],
                   "timestamp": _mongo_block["timestamp"], "oculusId": _mongo_block.get("oculusId"),
                   "expireAt": _mongo_block.get("expireAt")
               }
   elif OculusId and _is_auth_whitelisted:
       bcol = _get_blocked_col()
       if bcol is not None:
           _existing = bcol.find_one({"oculusId": str(OculusId)})
           if _existing:
               _epid = _existing.get("playFabId")
               remove_permanent_block(_epid)
               blocked_playfab_ids.pop(_epid, None)
               print(f"[Auth] Cleared block for whitelisted player {_epid} (oculus {OculusId})")

   _pre_block = None
   if CustomId:
       for pid, binfo in blocked_playfab_ids.items():
           cached = playfabCache.get(pid, {})
           if cached.get("CustomId") == CustomId or cached.get("ServerCustomId") == CustomId:
               if not _is_block_expired(binfo):
                   _pre_block = (pid, binfo)
               else:
                   # expired, remove
                   remove_permanent_block(pid)
                   blocked_playfab_ids.pop(pid, None)
               break
   if _pre_block:
       _blocked_pid, _binfo = _pre_block
       _pre_whitelisted = (
           str(OculusId) in HB_BYPASS_WHITELIST_OCULUS
           or client_ip in HB_BYPASS_WHITELIST_IPS
       )
       if _pre_whitelisted:
           remove_permanent_block(_blocked_pid)
           send_alert("Whitelisted Player Auto-Unblocked (Pre-Login)", [
               {"name": "PlayFab ID", "value": f"```{_blocked_pid}```", "inline": True},
               {"name": "Oculus ID", "value": f"```{OculusId or 'N/A'}```", "inline": True},
               {"name": "IP", "value": f"```{client_ip}```", "inline": True},
               {"name": "Was Blocked For", "value": f"```{_binfo['type']}```", "inline": True},
               {"name": "Status", "value": "```UNBLOCKED - player is whitelisted```", "inline": False}
           ], 0x00FF00)
       else:
           send_alert("Blocked Player Auth Attempt", [
               {"name": "PlayFab ID", "value": _blocked_pid, "inline": True},
               {"name": "IP", "value": client_ip, "inline": True},
               {"name": "Block Reason", "value": _binfo["reason"], "inline": False},
               {"name": "Cheat Type", "value": _binfo["type"], "inline": True},
               {"name": "Blocked At", "value": _binfo["timestamp"], "inline": True}
           ], 0x8B0000)
           return jsonify({"Message": "You are not allowed to authenticate.", "Error": "AUTH_BLOCKED"}), 403

   c = {
       "User-Agent": "PASSED",
       "CustomId": "N/A", "Nonce": "N/A", "AppId": "N/A", "Platform": "N/A",
       "OculusId": "N/A", "HWID": "N/A",
       "AppId Match": "SKIPPED", "Platform Check": "SKIPPED",
       "Oculus Nonce Auth": "SKIPPED", "OrgScope Check": "SKIPPED",
       "CustomId Match": "SKIPPED", "Entitlement": "SKIPPED", "Attestation": "SKIPPED",
       "PlayFab Login": "SKIPPED", "HWID Check": "SKIPPED", "PCVR Check": "PASSED"
   }
   alias_val = "N/A"
   server_cid = "N/A"
   playfab_id = "N/A"

   def send_fail(reason):
       embed_info = {
           "title": "PlayFab Auth Failed",
           "color": 0x8B0000,
           "fields": [
               {"name": "OculusId", "value": f"```{OculusId or 'N/A'}```", "inline": True},
               {"name": "IP", "value": f"```{client_ip}```", "inline": True},
               {"name": "Platform", "value": f"```{Platform or 'N/A'}```", "inline": True},
               {"name": "AppVersion", "value": f"```{AppVersion}```", "inline": True},
               {"name": "HWID", "value": f"```{HWID}```", "inline": True},
               {"name": "Device Model", "value": f"```{DeviceModel}```", "inline": True},
               {"name": "CustomId (Client)", "value": f"```{CustomId or 'N/A'}```", "inline": True},
               {"name": "CustomId (Server)", "value": f"```{server_cid}```", "inline": True},
               {"name": "Alias", "value": f"```{alias_val}```", "inline": True},
               {"name": "Failure Reason", "value": f"```{reason}```", "inline": False}
           ],
           "timestamp": datetime.now().isoformat(),
           "footer": {"text": "PlayFab Auth - 1/2"}
       }
       embed_checks = {
           "title": "Auth Checklist",
           "color": 0x8B0000,
           "fields": [
               {"name": "User-Agent", "value": f"```{c['User-Agent']}```", "inline": True},
               {"name": "CustomId", "value": f"```{c['CustomId']}```", "inline": True},
               {"name": "Nonce", "value": f"```{c['Nonce']}```", "inline": True},
               {"name": "AppId", "value": f"```{c['AppId']}```", "inline": True},
               {"name": "Platform", "value": f"```{c['Platform']}```", "inline": True},
               {"name": "OculusId", "value": f"```{c['OculusId']}```", "inline": True},
               {"name": "HWID", "value": f"```{c['HWID']}```", "inline": True},
               {"name": "AppId Match", "value": f"```{c['AppId Match']}```", "inline": True},
               {"name": "Platform Check", "value": f"```{c['Platform Check']}```", "inline": True},
               {"name": "PCVR Check", "value": f"```{c['PCVR Check']}```", "inline": True},
               {"name": "Oculus Nonce Auth", "value": f"```{c['Oculus Nonce Auth']}```", "inline": True},
               {"name": "OrgScope Check", "value": f"```{c['OrgScope Check']}```", "inline": True},
               {"name": "CustomId Match", "value": f"```{c['CustomId Match']}```", "inline": True},
               {"name": "Entitlement", "value": f"```{c['Entitlement']}```", "inline": True},
               {"name": "Attestation", "value": f"```{c['Attestation']}```", "inline": True},
               {"name": "PlayFab Login", "value": f"```{c['PlayFab Login']}```", "inline": True},
               {"name": "HWID Check", "value": f"```{c['HWID Check']}```", "inline": True}
           ],
           "timestamp": datetime.now().isoformat(),
           "footer": {"text": "PlayFab Auth - 2/2"}
       }
       send_webhook([embed_info, embed_checks])

   if CustomId is None:
       c["CustomId"] = "MISSING"
       record_auth_failure(client_ip, "MISSING_CUSTOM_ID", "CustomId parameter was not sent",
                           oculus_id=str(OculusId or "N/A"), hwid=str(HWID))
       send_fail("Missing CustomId parameter")
       return jsonify({"Message": "Failed To Validate Account Ownership.", "Error": "FailedRequestNoCustomId"}), 403
   c["CustomId"] = "PROVIDED"

   if Nonce is None:
       c["Nonce"] = "MISSING"
       record_auth_failure(client_ip, "MISSING_NONCE", "Nonce parameter was not sent",
                           oculus_id=str(OculusId or "N/A"), hwid=str(HWID))
       send_fail("Missing Nonce parameter")
       return jsonify({"Message": "Failed To Validate Account Ownership.", "Error": "FailedRequestNoNonce"}), 403
   c["Nonce"] = "PROVIDED"

   if AppId is None:
       c["AppId"] = "MISSING"
       record_auth_failure(client_ip, "MISSING_APP_ID", "AppId parameter was not sent",
                           oculus_id=str(OculusId or "N/A"), hwid=str(HWID))
       send_fail("Missing AppId parameter")
       return jsonify({"Message": "Failed To Validate AppId.", "Error": "FailedRequestNoAppId"}), 403
   c["AppId"] = "PROVIDED"

   if Platform is None:
       c["Platform"] = "MISSING"
       record_auth_failure(client_ip, "MISSING_PLATFORM", "Platform parameter was not sent",
                           oculus_id=str(OculusId or "N/A"), hwid=str(HWID))
       send_fail("Missing Platform parameter")
       return jsonify({"Message": "Unable To Validate Platform", "Error": "Platform Validation Failed"}), 403
   c["Platform"] = "PROVIDED"

   if OculusId is None:
       c["OculusId"] = "MISSING"
       record_auth_failure(client_ip, "MISSING_OCULUS_ID", "OculusId parameter was not sent",
                           oculus_id="N/A", hwid=str(HWID))
       send_fail("Missing OculusId parameter")
       return jsonify({"Message": "Failed To Validate Account Ownership.", "Error": "FailedRequestNoOculusId"}), 403
   c["OculusId"] = "PROVIDED"

   if HWID:
       c["HWID"] = "PROVIDED"
   else:
       c["HWID"] = "GENERATED" if GENERATE_PSEUDO_HWID else "MISSING (ALLOWED)"

   if settings.appidcheck and AppId != settings.TitleId:
       c["AppId Match"] = f"FAILED ({AppId})"
       record_auth_failure(client_ip, "WRONG_APP_ID", f"Expected {settings.TitleId}, got {AppId}",
                           oculus_id=str(OculusId or "N/A"), hwid=str(HWID))
       send_fail(f"Wrong AppId: got {AppId}, expected {settings.TitleId}")
       return jsonify({"Message": "Failed To Validate AppId.", "Error": "BadRequestAppIdMismatch"}), 403
   c["AppId Match"] = "PASSED" if settings.appidcheck else "SKIPPED (appidcheck off)"

   if Platform in ("Windows", "PC", "SteamVR"):
       c["Platform Check"] = f"FAILED ({Platform})"
       send_fail(f"Platform must be Quest, got {Platform}")
       return jsonify({"Message": "Failed To Validate Platform.", "Error": "ForbiddenPlatform"}), 403
   c["Platform Check"] = "PASSED"

   is_valid, server_custom_id, alias, error_reason = ValidateOculusAccount(
       Nonce=Nonce, OculusId=OculusId, ClientCustomId=CustomId
   )

   if not is_valid:
       if error_reason == "Nonce validation failed":
           c["Oculus Nonce Auth"] = "FAILED"
           record_auth_failure(client_ip, "NONCE_VALIDATION_FAILED",
                               "Oculus returned is_valid=false for nonce",
                               oculus_id=str(OculusId), hwid=str(HWID))
       elif error_reason == "CustomId mismatch":
           c["Oculus Nonce Auth"] = "PASSED"
           c["OrgScope Check"] = "PASSED"
           c["CustomId Match"] = "FAILED"
           record_auth_failure(client_ip, "CUSTOM_ID_MISMATCH",
                               "Client CustomId did not match server OrgScope",
                               oculus_id=str(OculusId), hwid=str(HWID))
       elif error_reason == "Invalid CustomId prefix":
           c["Oculus Nonce Auth"] = "PASSED"
           c["CustomId Match"] = "FAILED (bad prefix)"
           record_auth_failure(client_ip, "INVALID_CUSTOM_ID_PREFIX",
                               f"CustomId had unrecognised prefix: {CustomId[:10] if CustomId else 'N/A'}",
                               oculus_id=str(OculusId), hwid=str(HWID))
       elif "org_scoped_id" in (error_reason or "") or "alias" in (error_reason or ""):
           c["Oculus Nonce Auth"] = "PASSED"
           c["OrgScope Check"] = "FAILED"
           record_auth_failure(client_ip, "ORG_SCOPE_FAILED",
                               f"Oculus OrgScope lookup failed: {error_reason}",
                               oculus_id=str(OculusId), hwid=str(HWID))
       else:
           c["Oculus Nonce Auth"] = "PASSED"
           c["OrgScope Check"] = "FAILED"
           record_auth_failure(client_ip, "OCULUS_VALIDATION_FAILED",
                               f"Oculus validation error: {error_reason}",
                               oculus_id=str(OculusId), hwid=str(HWID))
       send_fail(f"Oculus validation: {error_reason}")
       return jsonify({"Message": "Failed To Validate Account Ownership.", "Error": "ForbiddenValidationFailed"}), 403

   c["Oculus Nonce Auth"] = "PASSED"
   c["OrgScope Check"] = "PASSED"
   c["CustomId Match"] = "PASSED"
   alias_val = alias
   server_cid = server_custom_id

   entitled, entitlement_error, entitlement_response = CheckUserEntitlement(OculusId)
   if not entitled:
       c["Entitlement"] = "FAILED"
       record_auth_failure(client_ip, "ENTITLEMENT_FAILED",
                           f"User does not own the app: {entitlement_error}",
                           oculus_id=str(OculusId), hwid=str(HWID))
       send_fail(f"Entitlement: {entitlement_error}")
       return jsonify({"Message": "You do not own this application.", "Error": "ForbiddenNotEntitled"}), 403
   c["Entitlement"] = "PASSED"

   attested, attestation_reason = has_valid_attestation(OculusId, client_ip)
   if not attested:
       c["Attestation"] = f"FAILED ({attestation_reason})"
       record_auth_failure(client_ip, "ATTESTATION_FAILED", attestation_reason,
                           oculus_id=str(OculusId), hwid=str(HWID))
       send_fail(f"Attestation: {attestation_reason}")
       return jsonify({"Message": "Device attestation required.", "Error": "ATTESTATION_FAILED"}), 403
   c["Attestation"] = "PASSED"

   custom_id = server_custom_id
   print(f"Validated user with alias: {alias}")

   if custom_id == "OCULUS0" or (CustomId and "OCULUS0" in CustomId):
       target_pid = rjson.get("currentPlayerId")
       ban_req = requests.post(
           url=f"https://{settings.TitleId}.playfabapi.com/Admin/BanUsers",
           json={"Bans": [{"PlayFabId": target_pid, "DurationInHours": None, "Reason": "CHEATING - LemonLoader Detected"}]},
           headers=settings.GetAuthHeaders()
       )
       c["PlayFab Login"] = "BANNED (Lemonloader)"
       send_fail("Auto-banned: OCULUS0 detected (Lemonloader)")
       add_violation(target_pid, "MODDED_CLIENT", "LemonLoader detected", "CRITICAL")
       return jsonify({"Message": "Banned for: Lemonloader", "Error": "Banned"}), 403

   login_request = requests.post(
       url=f"https://{settings.TitleId}.playfabapi.com/Server/LoginWithServerCustomId",
       json={"ServerCustomId": custom_id, "CreateAccount": True},
       headers=settings.GetAuthHeaders()
   )

   if login_request.status_code == 200:
       data = login_request.json().get("data")
       playFabId = data.get("PlayFabId")

       if detect_pcvr(playFabId, Platform, DeviceModel, user_agent):
           c["PlayFab Login"] = "BLOCKED (PCVR)"
           c["PCVR Check"] = "FAILED"
           send_fail(f"PCVR detected: Platform={Platform}, Device={DeviceModel}")
           return jsonify({
               "Message": "PC VR is not supported. Quest headset required.",
               "Error": "PCVR_BLOCKED"
           }), 403

       sessionTicket = data.get("SessionTicket")
       entityToken = data.get("EntityToken").get("EntityToken")
       entityType = data.get("EntityToken").get("Entity").get("Type")
       entityId = data.get("EntityToken").get("Entity").get("Id")

       print(requests.post(
           url=f"https://{settings.TitleId}.playfabapi.com/Server/LinkServerCustomId",
           json={"ForceLink": True, "ServerCustomId": custom_id, "PlayFabId": playFabId},
           headers=settings.GetAuthHeaders()
       ).json())

       AccountCreationIsoTimestamp_req = requests.post(
           url=f"https://{settings.TitleId}.playfabapi.com/Server/GetUserAccountInfo",
           json={"PlayFabId": playFabId},
           headers=settings.GetAuthHeaders()
       )
       account_data = AccountCreationIsoTimestamp_req.json()
       AccountCreationIsoTimestamp = account_data.get("data", {}).get("UserInfo", {}).get("Created")
       title_info = account_data.get("data", {}).get("UserInfo", {}).get("TitleInfo", {})
       ingame_name = title_info.get("DisplayName") or account_data.get("data", {}).get("UserInfo", {}).get("Username") or alias or "N/A"

       playfabCache.setdefault(playFabId, {})
       playfabCache[playFabId]["CustomId"] = CustomId
       playfabCache[playFabId]["ServerCustomId"] = custom_id
       playfabCache[playFabId]["OculusId"] = OculusId
       playfabCache[playFabId]["Alias"] = alias
       playfabCache[playFabId]["ip"] = client_ip
       playfabCache[playFabId]["HWID"] = HWID

       active_sessions[playFabId] = {
           "oculus_id": OculusId, "alias": alias, "ip": client_ip,
           "hwid": HWID, "session_ticket": sessionTicket, "login_time": time.time()
       }

       if is_playfab_blocked(playFabId):
           binfo = blocked_playfab_ids[playFabId]
           _auth_whitelisted = (
               str(OculusId) in HB_BYPASS_WHITELIST_OCULUS
               or client_ip in HB_BYPASS_WHITELIST_IPS
           )
           if _auth_whitelisted:
               remove_permanent_block(playFabId)
               send_alert("Whitelisted Player Auto-Unblocked (PlayFab Auth)", [
                   {"name": "PlayFab ID", "value": f"```{playFabId}```", "inline": True},
                   {"name": "Oculus ID", "value": f"```{OculusId}```", "inline": True},
                   {"name": "IP", "value": f"```{client_ip}```", "inline": True},
                   {"name": "Was Blocked For", "value": f"```{binfo['type']}```", "inline": True},
                   {"name": "Status", "value": "```UNBLOCKED - player is whitelisted```", "inline": False}
               ], 0x00FF00)
               print(f"[Auth] Auto-unblocked whitelisted player {playFabId}")
           else:
               send_alert("Blocked Player Auth Attempt (Post-Login)", [
                   {"name": "PlayFab ID", "value": playFabId, "inline": True},
                   {"name": "In-Game Name", "value": ingame_name, "inline": True},
                   {"name": "IP", "value": client_ip, "inline": True},
                   {"name": "Block Reason", "value": binfo["reason"], "inline": False},
                   {"name": "Cheat Type", "value": binfo["type"], "inline": True},
                   {"name": "Blocked At", "value": binfo["timestamp"], "inline": True}
               ], 0x8B0000)
               _drop_session(str(OculusId))
               active_sessions.pop(playFabId, None)
               c["PlayFab Login"] = "BLOCKED"
               send_fail(f"Auth blocked: {binfo['type']} - {binfo['reason']}")
               return jsonify({"Message": "You are not allowed to authenticate.", "Error": "AUTH_BLOCKED"}), 403

       if settings.EnableAccountAgeCheck and settings.MinimumAccountAgeDays > 0:
           created_date = datetime.fromisoformat(AccountCreationIsoTimestamp.replace("Z", "+00:00"))
           age_days = (datetime.now(timezone.utc) - created_date).days
           if age_days < settings.MinimumAccountAgeDays:
               send_fail(f"Account too new: {age_days} days old (minimum {settings.MinimumAccountAgeDays})")
               return jsonify({"Message": "Account too new to play", "Error": "ACCOUNT_TOO_NEW"}), 403

       session_token = generate_session_token(playFabId)
       trust_score = calculate_trust_score(playFabId)
       hb_secret = issue_hb_secret(OculusId, playFabId, client_ip=client_ip)

       response_body = {
           "SessionTicket": sessionTicket, "EntityToken": entityToken,
           "PlayFabId": playFabId, "EntityId": entityId, "EntityType": entityType,
           "AccountCreationIsoTimestamp": AccountCreationIsoTimestamp,
           "SessionToken": session_token, "TrustScore": trust_score,
           "HeartbeatSecret": hb_secret
       }
       print(json.dumps(response_body, indent=2))

       c["PlayFab Login"] = "AUTHED"
       c["HWID Check"] = "PASSED"

       embed_info = {
           "title": "PlayFab Auth Success", "color": 0x00FF00,
           "fields": [
               {"name": "PlayFabId", "value": f"```{playFabId}```", "inline": True},
               {"name": "In-Game Name", "value": f"```{ingame_name}```", "inline": True},
               {"name": "OculusId", "value": f"```{OculusId}```", "inline": True},
               {"name": "Alias", "value": f"```{alias}```", "inline": True},
               {"name": "IP", "value": f"```{client_ip}```", "inline": True},
               {"name": "HWID", "value": f"```{HWID}```", "inline": True},
               {"name": "Trust Score", "value": f"```{trust_score}```", "inline": True},
               {"name": "Platform", "value": f"```{Platform}```", "inline": True},
               {"name": "Device Model", "value": f"```{DeviceModel}```", "inline": True},
               {"name": "AppVersion", "value": f"```{AppVersion}```", "inline": True},
               {"name": "CustomId (Client)", "value": f"```{CustomId}```", "inline": True},
               {"name": "CustomId (Server)", "value": f"```{custom_id}```", "inline": True},
               {"name": "Account Created", "value": f"```{AccountCreationIsoTimestamp}```", "inline": False}
           ],
           "timestamp": datetime.now().isoformat(),
           "footer": {"text": "PlayFab Auth - 1/2"}
       }
       embed_checks = {
           "title": "Auth Checklist", "color": 0x00FF00,
           "fields": [
               {"name": "User-Agent", "value": "```PASSED```", "inline": True},
               {"name": "HWID Check", "value": "```PASSED```", "inline": True},
               {"name": "PCVR Check", "value": "```PASSED```", "inline": True},
               {"name": "AppId Match", "value": "```PASSED```", "inline": True},
               {"name": "Platform Check", "value": "```PASSED```", "inline": True},
               {"name": "Oculus Nonce Auth", "value": "```PASSED```", "inline": True},
               {"name": "OrgScope Check", "value": "```PASSED```", "inline": True},
               {"name": "CustomId Match", "value": "```PASSED```", "inline": True},
               {"name": "Entitlement", "value": "```VERIFIED```", "inline": True},
               {"name": "Attestation", "value": "```PASSED```", "inline": True},
               {"name": "PlayFab Login", "value": "```AUTHED```", "inline": True},
               {"name": "VPN Check", "value": "```PASSED```", "inline": True},
               {"name": "IP Ban Check", "value": "```PASSED```", "inline": True},
               {"name": "HWID Ban Check", "value": "```PASSED```", "inline": True}
           ],
           "timestamp": datetime.now().isoformat(),
           "footer": {"text": "PlayFab Auth - 2/2"}
       }
       send_webhook([embed_info, embed_checks])

       return jsonify(response_body), 200

   else:
       c["PlayFab Login"] = "FAILED"
       if login_request.status_code == 403:
           ban_info = login_request.json()
           if ban_info.get("errorCode") == 1002:
               ban_details = ban_info.get("errorDetails", {})
               ban_expiration_key = next(iter(ban_details.keys()), None)
               ban_expiration_list = ban_details.get(ban_expiration_key, [])
               ban_expiration = ban_expiration_list[0] if ban_expiration_list else "No expiration date provided."
               add_violation(playfab_id, "BANNED_ACCOUNT", ban_expiration_key, "CRITICAL")
               send_fail(f"User is banned: {ban_expiration_key} until {ban_expiration}")
               return jsonify({"BanMessage": ban_expiration_key, "BanExpirationTime": ban_expiration}), 403
           else:
               error_message = ban_info.get("errorMessage", "Forbidden without ban information.")
               send_fail(f"PlayFab error: {error_message}")
               return jsonify({"Error": "PlayFab Error", "Message": error_message}), 403
       else:
           error_info = login_request.json()
           error_message = error_info.get("errorMessage", "An error occurred.")
           send_fail(f"PlayFab login error: {error_message}")
           return jsonify({"Error": "PlayFab Error", "Message": error_message}), login_request.status_code

# ---------- Photon Authentication ----------
@app.route("/api/photon", methods=["POST", "GET"])
@rate_limit(max_requests=30, window_seconds=60)
def photonauth():
   print(f"Received {request.method} request at /api/photon")
   AuthTicketUrl = f"https://{settings.TitleId}.playfabapi.com/Server/AuthenticateSessionTicket"
   VALID_APPS = [f"{settings.TitleId}"]

   if request.method == "GET":
       PlayerId = request.args.get("username")
       token = request.args.get("token")
       if not PlayerId or not token:
           return jsonify({"resultCode": 3, "message": "Failed to parse token from request", "userId": None, "nickname": None}), 400
       print(f"Player: {PlayerId} Has Authed In Old Update.")
       return jsonify({"resultCode": 1, "message": f"User: {PlayerId} Was Authed.", "username": PlayerId, "token": token}), 200

   elif request.method == "POST":
       newData = request.get_json()
       AppId = newData.get("AppId")
       AppVersion = newData.get("AppVersion")
       Ticket = newData.get("Ticket")
       Token = newData.get("Token")
       Nonce = newData.get("Nonce")
       Platform = newData.get("Platform")
       anti_lib_status = newData.get("AntiLibStatus", "Passed")

       print(json.dumps(newData, indent=2))

       if not Ticket:
           print("[Photon] FAIL-CLOSED: Ticket is null/empty")
           return jsonify({"ResultCode": 3, "Message": "Missing Ticket parameter", "Error": "BadRequestNoTicket"}), 403

       if not Platform:
           print("[Photon] FAIL-CLOSED: Platform is null/empty")
           add_violation(None, "INVALID_PLATFORM", "Platform was null/empty - fail-closed", "HIGH")
           return jsonify({"ResultCode": 3, "Message": "Missing Platform parameter", "Error": "BadRequestNoPlatform"}), 403

       if settings.appidcheck and AppId not in VALID_APPS:
           print(f"Invalid AppId: {AppId}")
           return jsonify({"ResultCode": 2, "Message": "Invalid AppId parameter", "Error": "BadRequestWrongAppId"}), 403

       if Platform != "Quest":
           print("Users Platform Is Not Quest")
           add_violation(None, "INVALID_PLATFORM", f"Platform: {Platform}", "HIGH")
           return jsonify({"Error": "Bad request", "ResultCode": 3, "Message": "Platform Must Be Quest Fella"}), 403

       # PCVR check in Photon (UA only)
       if ENFORCE_PCVR_BAN:
           photon_ua = request.headers.get("User-Agent", "").lower()
           _pcvr_ua_hit = None
           for kw in PCVR_UA_KEYWORDS:
               if kw in photon_ua:
                   _pcvr_ua_hit = kw
                   break
           if _pcvr_ua_hit:
               client_ip_photon = request.headers.get("X-Forwarded-For", request.remote_addr)
               if client_ip_photon and "," in client_ip_photon:
                   client_ip_photon = client_ip_photon.split(",")[0].strip()
               send_alert("PCVR BLOCKED - Photon Gate", [
                   {"name": "IP", "value": f"```{client_ip_photon}```", "inline": True},
                   {"name": "Platform (claimed)", "value": f"```{Platform}```", "inline": True},
                   {"name": "UA Keyword", "value": f"```{_pcvr_ua_hit}```", "inline": True},
                   {"name": "User-Agent", "value": f"```{photon_ua[:150]}```", "inline": False},
               ], 0xFF0000)
               return jsonify({
                   "ResultCode": 2,
                   "Message": "PC VR is not supported. Quest headset required.",
                   "Error": "PCVR_BLOCKED"
               }), 403

       AuthSessionTicketReq = requests.post(
           url=AuthTicketUrl, json={"SessionTicket": Ticket}, headers=settings.GetAuthHeaders()
       )
       print(AuthSessionTicketReq)

       if AuthSessionTicketReq.status_code != 200:
           print(f"SessionTicket: {Ticket} Is Invalid")
           add_violation(None, "INVALID_SESSION_TICKET", f"Ticket: {Ticket[:20]}...", "MEDIUM")
           return jsonify({"ResultCode": 2, "Message": "Invalid SessionTicket parameter", "Error": "BadRequestBadSessionTicket"}), 403

       getdata = AuthSessionTicketReq.json().get("data", {}).get("UserInfo", {})
       UserId = getdata.get("PlayFabId")

       # Master whitelist
       _photon_sess = active_sessions.get(UserId, {})
       _photon_cache = playfabCache.get(UserId, {})
       _photon_oid = _photon_sess.get("oculus_id") or _photon_cache.get("OculusId") or _oculus_for_playfab(UserId) or "N/A"
       _photon_ip = _photon_sess.get("ip") or _photon_cache.get("ip") or "N/A"
       if _photon_ip == "N/A":
           _ps = _load_hb_session(_photon_oid) if _photon_oid != "N/A" else None
           if _ps:
               _photon_ip = _ps.get("ip") or "N/A"

       _photon_master_wl = (
           (_photon_oid != "N/A" and _photon_oid in HB_BYPASS_WHITELIST_OCULUS)
           or _photon_ip in HB_BYPASS_WHITELIST_IPS
       )
       if _photon_master_wl:
           if UserId in blocked_playfab_ids:
               remove_permanent_block(UserId)
               blocked_playfab_ids.pop(UserId, None)
           bcol_wl_pm = _get_blocked_col()
           if bcol_wl_pm is not None:
               try:
                   bcol_wl_pm.delete_one({"playFabId": UserId})
               except:
                   pass
           print(f"[Photon] MASTER WHITELIST: {UserId} (oculus={_photon_oid} ip={_photon_ip}) - skipping ALL checks")
           return jsonify({
               "ResultCode": 1, "Message": "Whitelisted",
               "AppId": AppId, "AppVersion": AppVersion, "Nonce": Nonce,
               "OculusId": _photon_oid, "Ticket": Ticket, "Token": Token, "UserId": UserId
           }), 200

       session = active_sessions.get(UserId, {})
       cache = playfabCache.get(UserId, {})
       oculus_id = session.get("oculus_id") or cache.get("OculusId")

       if not oculus_id:
           oculus_id = _oculus_for_playfab(UserId)
       if not oculus_id:
           bcol_oid = _get_blocked_col()
           if bcol_oid is not None:
               try:
                   _bdoc = bcol_oid.find_one({"playFabId": UserId})
                   if _bdoc:
                       oculus_id = _bdoc.get("oculusId")
               except:
                   pass
       if not oculus_id:
           hb_col_oid = _get_hb_col()
           if hb_col_oid is not None:
               try:
                   _hbdoc = hb_col_oid.find_one({"playfabId": UserId})
                   if _hbdoc:
                       oculus_id = _hbdoc.get("oculusId")
               except:
                   pass
       if not oculus_id:
           oculus_id = "N/A"

       alias = session.get("alias") or cache.get("Alias") or "N/A"
       client_ip = session.get("ip") or cache.get("ip") or "N/A"
       if client_ip == "N/A":
           sess_doc = _load_hb_session(oculus_id) if oculus_id != "N/A" else None
           if sess_doc:
               client_ip = sess_doc.get("ip") or "N/A"
       if client_ip == "N/A":
           hb_doc_ip = hb_read(oculus_id) if oculus_id != "N/A" else {}
           client_ip = hb_doc_ip.get("ip") or "N/A"

       photon_request_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
       if photon_request_ip and "," in photon_request_ip:
           photon_request_ip = photon_request_ip.split(",")[0].strip()

       ingame_name = get_ingame_name(UserId)
       trust_score = calculate_trust_score(UserId)

       device_id = oculus_id or "N/A"
       if device_id != "N/A" and is_device_banned(str(device_id)):
           send_alert("DEVICE BANNED - Photon Denied", [
               {"name": "PlayFab ID", "value": f"```{UserId}```", "inline": True},
               {"name": "Device ID", "value": f"```{device_id}```", "inline": True},
           ], 0x8B0000)
           return jsonify({"ResultCode": 2, "Message": "Device is banned."}), 403

       if oculus_id != "N/A" and is_device_banned(str(oculus_id)):
           send_alert("DEVICE BANNED - Photon Denied", [
               {"name": "PlayFab ID", "value": f"```{UserId}```", "inline": True},
               {"name": "Oculus ID", "value": f"```{oculus_id}```", "inline": True},
           ], 0x8B0000)
           return jsonify({"ResultCode": 2, "Message": "Device is banned."}), 403

       if oculus_id != "N/A" and ENFORCE_HEARTBEAT:
           _is_whitelisted = (
               oculus_id in HB_BYPASS_WHITELIST_OCULUS
               or client_ip in HB_BYPASS_WHITELIST_IPS
           )
           if _is_whitelisted:
               print(f"[Photon] HB BYPASS: oculus={oculus_id} ip={client_ip} - whitelisted, skipping heartbeat checks")
           else:
               _hb_debug = hb_read(oculus_id)
               _hb_last = _hb_debug.get("last_heartbeat", 0)
               _hb_age = f"{time.time() - _hb_last:.1f}s" if _hb_last else "NEVER"
               print(f"[Photon] HB check: user={UserId} oculus={oculus_id} last_hb={_hb_last} age={_hb_age}")

               att_ok, att_reason = has_valid_attestation(oculus_id, client_ip=client_ip)
               if not att_ok:
                   print(f"[Photon] Attestation gate failed for {UserId} (oculus {oculus_id}): {att_reason}")
                   if att_reason.startswith("attestation_expired") or att_reason == "no_attestation":
                       return jsonify({
                           "ResultCode": 2,
                           "Message": "Device verification required. Please relaunch.",
                           "Error": "ATTESTATION_REQUIRED"
                       }), 403
                   add_permanent_block(
                       UserId,
                       "AUTOMATED DETECTION: XREAC - CHEATING OR EXPLOITING\nIF THIS WAS A FALSE DETECTION, PLEASE MAKE AN APPEAL IN:\ndiscord.gg/bwZ3P84EFw",
                       "ATTESTATION_FAILED",
                       oculus_id=oculus_id
                   )
                   send_alert("AUTOMATED DETECTION: XREAC - Cheating or Exploiting", [
                       {"name": "PlayFab ID", "value": f"```{UserId}```", "inline": True},
                       {"name": "Oculus ID", "value": f"```{oculus_id}```", "inline": True},
                       {"name": "IP", "value": f"```{client_ip}```", "inline": True},
                       {"name": "Detail", "value": f"```Meta attestation failed: {att_reason}```", "inline": False},
                       {"name": "Action", "value": "```Photon BLOCKED - Appeal at discord.gg/bwZ3P84EFw```", "inline": False}
                   ], 0xFF6600)
                   active_sessions.pop(UserId, None)
                   _drop_session(oculus_id)
                   return jsonify({"ResultCode": 2, "Message": "Client verification failed", "Error": "ATTESTATION_FAILED"}), 403

               beat_state, beat_reason = photon_beat_status(oculus_id, UserId)

               if beat_state == "not_ready":
                   now = time.time()
                   tracker = _hb_not_ready_attempts[oculus_id]
                   if now - tracker["first_at"] > HB_NOT_READY_WINDOW:
                       tracker["count"] = 1
                       tracker["first_at"] = now
                   else:
                       tracker["count"] += 1

                   if tracker["count"] < HB_NOT_READY_MAX:
                       print(f"[Photon] HB not ready for {UserId} (attempt {tracker['count']}/{HB_NOT_READY_MAX}) - soft reject")
                       return jsonify({
                           "ResultCode": 2,
                           "Message": "Anti-cheat not initialized. Retry in 5s.",
                           "Error": "HB_NOT_READY"
                       }), 403

                   print(f"[Photon] HB never initialized after {HB_NOT_READY_MAX} attempts for {UserId} - Photon block")
                   # ---- NO BLOCK: just return error, let them retry ----
                   send_alert("HEARTBEAT NEVER INITIALIZED - Retry", [
                       {"name": "PlayFab ID", "value": f"```{UserId}```", "inline": True},
                       {"name": "Oculus ID", "value": f"```{oculus_id}```", "inline": True},
                       {"name": "IP", "value": f"```{client_ip}```", "inline": True},
                       {"name": "Detail", "value": f"```HB lib never initialized after {HB_NOT_READY_MAX} attempts```", "inline": False},
                       {"name": "Action", "value": "```Soft reject - try again```", "inline": False}
                   ], 0xFFA500)
                   # Instead of blocking, just return error
                   return jsonify({"ResultCode": 2, "Message": "Anti-cheat not initialized. Please restart the game.", "Error": "HB_NOT_READY"}), 403

               elif beat_state == "stale":
                   print(f"[Photon] Stale heartbeat for {UserId} (oculus {oculus_id}): {beat_reason}")
                   # ---- NO BLOCK: just return error, let them retry ----
                   send_alert("HEARTBEAT STALE - Retry", [
                       {"name": "PlayFab ID", "value": f"```{UserId}```", "inline": True},
                       {"name": "Oculus ID", "value": f"```{oculus_id}```", "inline": True},
                       {"name": "IP", "value": f"```{client_ip}```", "inline": True},
                       {"name": "Detail", "value": f"```Heartbeat went stale ({beat_reason})```", "inline": False},
                       {"name": "Action", "value": "```Soft reject - try again```", "inline": False}
                   ], 0xFFA500)
                   return jsonify({"ResultCode": 2, "Message": "Heartbeat lost. Please restart the game.", "Error": "HEARTBEAT_STALE"}), 403

               _hb_not_ready_attempts.pop(oculus_id, None)

       _photon_whitelisted = (
           (oculus_id != "N/A" and oculus_id in HB_BYPASS_WHITELIST_OCULUS)
           or client_ip in HB_BYPASS_WHITELIST_IPS
       )
       if _photon_whitelisted:
           if UserId in blocked_playfab_ids:
               remove_permanent_block(UserId)
               blocked_playfab_ids.pop(UserId, None)
               print(f"[Photon] Cleared block for whitelisted player {UserId}")
           bcol_wl_p = _get_blocked_col()
           if bcol_wl_p is not None:
               try:
                   bcol_wl_p.delete_one({"playFabId": UserId})
               except:
                   pass

       # Load block from MongoDB if not in memory
       if not _photon_whitelisted and UserId and not is_playfab_blocked(UserId):
           pass  # already checked in is_playfab_blocked
       is_blocked = is_playfab_blocked(UserId)
       anti_lib_failed = str(anti_lib_status).lower() in ["false", "failed"]

       if is_blocked or anti_lib_failed:
           if is_blocked:
               reason = blocked_playfab_ids[UserId]["reason"]
               cheat_type = blocked_playfab_ids[UserId]["type"]
           else:
               reason = "Native Anti-Cheat Library Verification Failed"
               cheat_type = "ANTI_LIB_FAILED"
               add_violation(UserId, "MODDED_CLIENT", reason, "CRITICAL")
               add_permanent_block(UserId, reason, cheat_type, oculus_id=oculus_id)

           print(f"[Photon] Player blocked from Photon: {UserId} ({cheat_type})")
           send_webhook({
               "title": "PLAYER BLOCKED FROM PHOTON", "color": 0xFF6600,
               "description": "Player was denied entry to Photon.",
               "fields": [
                   {"name": "PlayFab ID", "value": f"```{UserId}```", "inline": True},
                   {"name": "In-Game Name", "value": f"```{ingame_name}```", "inline": True},
                   {"name": "Meta Alias", "value": f"```{alias}```", "inline": True},
                   {"name": "Oculus ID", "value": f"```{oculus_id}```", "inline": True},
                   {"name": "IP Address", "value": f"```{client_ip}```", "inline": True},
                   {"name": "Block Type", "value": f"```{cheat_type}```", "inline": True},
                   {"name": "Reason", "value": f"```{reason}```", "inline": False},
                   {"name": "Anti-Lib Status", "value": f"```{anti_lib_status}```", "inline": True},
                   {"name": "Trust Score", "value": f"```{trust_score}```", "inline": True},
                   {"name": "Action", "value": "```Photon Denied - NO PlayFab Ban```", "inline": False},
               ],
               "timestamp": datetime.now().isoformat(),
               "footer": {"text": "Anti-Cheat - Photon Guard"}
           }, ALERT_WEBHOOK_URL)
           return jsonify({"ResultCode": 2, "Message": "You are not allowed to join servers.", "Error": "AUTH_BLOCKED"}), 403

       AccountInfoReq = requests.post(
           url=f"https://{settings.TitleId}.playfabapi.com/Server/GetUserAccountInfo",
           json={"PlayFabId": UserId}, headers=settings.GetAuthHeaders()
       )
       if AccountInfoReq.status_code != 200:
           print(f"Failed to get account info for UserId: {UserId}")
           return jsonify({"ResultCode": 3, "Message": "Failed to get account info", "Error": "BadRequestAccountInfo"}), 403

       accountData = AccountInfoReq.json().get("data", {}).get("UserInfo", {})
       print(f"AccountInfo response: {json.dumps(accountData, indent=2)}")
       ServerCustomIdInfo = accountData.get("ServerCustomIdInfo") or {}
       CustomId = ServerCustomIdInfo.get("CustomId") if ServerCustomIdInfo else None

       if not CustomId or not (CustomId.startswith("OCULUS") or CustomId.startswith("OC")):
           if oculus_id and oculus_id != "N/A":
               print(f"[Photon] ServerCustomId not yet propagated for {UserId} - trusting session oculus_id {oculus_id}")
               OculusId = oculus_id
               if not UserId or not (13 <= len(UserId) <= 16) or not all(c in "0123456789ABCDEFabcdef" for c in UserId):
                   print(f"UserId: {UserId} Failed hex/length validation (len={len(UserId) if UserId else 0})")
                   add_violation(UserId, "INVALID_USER_ID_FORMAT", f"UserId: {UserId}", "HIGH")
                   return jsonify({"ResultCode": 3, "Message": "Invalid UserId format", "Error": "BadRequestBadUserId"}), 403
               print(f"{UserId} Was Authed Successfully (via session fallback).")
               return jsonify({
                   "ResultCode": 1, "Message": "Yay Servers Work Ig",
                   "AppId": AppId, "AppVersion": AppVersion, "Nonce": Nonce,
                   "OculusId": OculusId, "Ticket": Ticket, "Token": Token, "UserId": UserId
               }), 200
           print(f"Invalid or missing ServerCustomId AND no session oculus_id: {CustomId}")
           add_violation(UserId, "INVALID_CUSTOM_ID", f"CustomId: {CustomId}", "HIGH")
           return jsonify({"ResultCode": 3, "Message": "Invalid ServerCustomId", "Error": "BadRequestInvalidCustomId"}), 403

       OrgScopedCustomId = CustomId[6:] if CustomId.startswith("OCULUS") else CustomId[2:]
       print(f"OrgScopedCustomId: {OrgScopedCustomId}")

       OrgScopeUrl = f"https://graph.oculus.com/{OrgScopedCustomId}?access_token={settings.AppCreds}"
       GetOculusIdReq = requests.get(url=OrgScopeUrl, headers={"Content-Type": "application/json"})

       if "error" in GetOculusIdReq.json():
           if oculus_id and oculus_id != "N/A":
               print(f"[Photon] OrgScope check failed but trusting session oculus_id {oculus_id}")
               OculusId = oculus_id
           else:
               print("User Did Not Pass The OrgScope Check.")
               add_violation(UserId, "ORG_SCOPE_FAILED", f"OrgScopedCustomId: {OrgScopedCustomId}", "HIGH")
               return jsonify({"ResultCode": 3, "Message": "Did Not Pass OrgScopeId Checker", "Error": "BadRequestInvalidOrgScopeId"}), 403
       else:
           OculusId = GetOculusIdReq.json().get("id")

       if not UserId or not (13 <= len(UserId) <= 16) or not all(c in "0123456789ABCDEFabcdef" for c in UserId):
           print(f"UserId: {UserId} Failed hex/length validation (len={len(UserId) if UserId else 0})")
           add_violation(UserId, "INVALID_USER_ID_FORMAT", f"UserId: {UserId}", "HIGH")
           return jsonify({"ResultCode": 3, "Message": "Invalid UserId format", "Error": "BadRequestBadUserId"}), 403

       print(f"Users OculusId Is: {OculusId}")
       print(f"{UserId} Was Authed Successfully.")
       return jsonify({
           "ResultCode": 1, "Message": "Yay Servers Work Ig",
           "AppId": AppId, "AppVersion": AppVersion, "Nonce": Nonce,
           "OculusId": OculusId, "Ticket": Ticket, "Token": Token, "UserId": UserId
       }), 200

# ---------- Remaining Endpoints ----------
@app.route("/api/CachePlayFabId", methods=["POST", "GET"])
@rate_limit(max_requests=30, window_seconds=60)
def cacheplatfabid():
   rjson = request.get_json()
   playfabCache[rjson.get("PlayFabId")] = rjson
   return jsonify({"Message": "Success"}), 200

@app.route('/api/TitleData', methods=['POST', 'GET'])  
def titledata():  
  response_data = {  
      "AutoMuteCheckedHours": {"hours": 169},  
      "AutoName_Adverbs": ["Cool", "Fine", "Bald", "Bold", "Half", "Only", "Calm", "Fab", "Ice", "Mad", "Rad", "Big", "New", "Old", "Shy"],  
      "AutoName_Nouns": ["Gorilla", "Chicken", "Darling", "Sloth", "King", "Queen", "Royal", "Major", "Actor", "Agent", "Elder", "Honey", "Nurse", "Doctor", "Rebel", "Shape", "Ally", "Driver", "Deputy"],  
      "CreditsData": [
          {  
              "Title": "<color=blue>STAFF</color>",  
              "Entries": [  
                  "KAINE (FOUNDER/ANTICHEAT MAKER/DEVELOPER)",  
                  "HAZYVR (OWNER)",  
                  "YOUR NAMES (OWNER",  
                  "YOUR NAMES (CO-OWNER)",
                  "YOUR NAMES (PLAYFAB-MANAGER)",
                  "YOUR NAMES (PLAYFAB-MANAGER)",
                  "YOUR NAMES (ADMIN)",
                  "YOUR NAMES (MOD)",
                  "YOUR NAMES (MOD)",
                  "YOUR NAMES (MOD)",
                  "YOUR NAMES-MOD)",
                  "YOUR NAMES (TRIAL-MOD)",
                  "YOUR NAMES (TRIAL-MOD)"
              ]  
          },  
          {  
              "Title": "<color=yellow>CREDITS</color>",  
              "Entries": ["KAINE FOR THE BUTTONS"] 
          },  
          {  
              "Title": "<color=red>TUFF FELLAS</color>",  
              "Entries": ["KAINE", "HAZYVR", "", ""]  
          }  
      ],  
      "BundleBoardSign": "<color=#E04E9D>YALE </color><color=#FF6250>TAG</color>",  
      "BundleKioskButton": "<color=#E04E9D>YALE </color><color=#FF6250>TAG</color>",  
      "BundleKioskSign": "<color=#E04E9D>YALE </color><color=#FF6250>TAG</color>",  
      "BundleLargeSign": "<color=#E04E9D>YALE </color><color=#FF6250>TAG</color>",  
      "EmptyFlashbackText": "FLOOR TWO NOW OPEN\n FOR BUSINESS\n\nSTILL SEARCHING FOR\nBOX LABELED 2021",  
      "EnableCustomAuthentication": True,  
      "GorillanalyticsChance": 4320,  
      "LatestPrivacyPolicyVersion": "2024.09.20",  
      "LatestTOSVersion": "2024.09.20",  
      "MOTD": "<color=#00FFFF>W</color><color=#00F5FF>E</color><color=#00EBFF>L</color><color=#00E1FF>C</color><color=#00D7FF>O</color><color=#00CDFF>M</color><color=#00C3FF>E</color> <color=#00AFFF>T</color><color=#00A5FF>O</color> <color=#0090FF>W</color><color=#0086FF>I</color><color=#007CFF>F</color><color=#0072FF>I</color> <color=#0054FF>T</color><color=#004AFF>A</color><color=#0040FF>G</color>",
      "SeasonalStoreBoardSign": "<color=purple>RATE THE GAME 5 STARS!</color>\n\n<color=aqua>WIFI TAG",  
      "TOS_2024.09.20": "WIFI TAG",  
      "TOBAlreadyOwnCompTxt": "WIFI TAG",  
      "TOBAlreadyOwnPurchaseBundle": "RETRO",  
      "TOBDefCompTxt": "WIFI TAG",  
      "TOBDefPurchaseBtnDefTxt": "RETRO",  
      "UseLegacyIAP": False  
  }  
  return jsonify(response_data)

@app.route("/api/GetAcceptedAgreements", methods=["POST", "GET"])
def GetAcceptedAgreements():
   return jsonify({"PrivacyPolicy": "1.1.67", "TOS": "11.05.22.2"}), 200

@app.route("/api/SubmitAcceptedAgreements", methods=["POST", "GET"])
def SubmitAcceptedAgreements():
   return jsonify({"PrivacyPolicy": "1.1.67", "TOS": "11.05.22.2"}), 200

@app.route("/api/GetName", methods=["POST", "GET"])
def GetName():
   return jsonify({"result": f"RUSH{random.randint(1000, 9999)}"})

@app.route("/api/ConsumeOculusIAP", methods=["POST", "GET"])
@rate_limit(max_requests=10, window_seconds=60)
def consumeoculusiap():
   rjson = request.get_json()
   userId = rjson.get("userID")
   nonce = rjson.get("nonce")
   sku = rjson.get("sku")
   req = requests.post(
       url=f"https://graph.oculus.com/consume_entitlement?nonce={nonce}&user_id={userId}&sku={sku}&access_token={settings.AppCreds}",
       headers={"content-type": "application/json"}
   )
   if bool(req.json().get("success")):
       return jsonify({"result": True})
   else:
       return jsonify({"error": True})

@app.route("/api/TryDistributeCurrencyV2", methods=["POST"])
def TryDistributeCurrencyV2():
   if request.method != "POST":
       return "", 404
   rjson = request.json
   sr_a_day = 500
   current_player_id = rjson.get("CallerEntityProfile", {}).get("Lineage", {}).get("MasterPlayerAccountId")
   get_data_response = requests.post(
       f"https://{settings.TitleId}.playfabapi.com/Server/GetUserReadOnlyData",
       headers=settings.GetAuthHeaders(),
       json={"PlayFabId": current_player_id, "Keys": ["DailyLogin"]}
   )
   daily_login_value = get_data_response.json().get("data", {}).get("Data", {}).get("DailyLogin", {}).get("Value")
   last_login_date = None
   if daily_login_value:
       last_login_date = datetime.fromisoformat(daily_login_value.replace("Z", "+00:00")).astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
   if not last_login_date or last_login_date < datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=timezone.utc):
       requests.post(
           f"https://{settings.TitleId}.playfabapi.com/Server/AddUserVirtualCurrency",
           headers=settings.GetAuthHeaders(),
           json={"PlayFabId": current_player_id, "VirtualCurrency": "SR", "Amount": sr_a_day}
       )
       requests.post(
           f"https://{settings.TitleId}.playfabapi.com/Server/UpdateUserReadOnlyData",
           headers=settings.GetAuthHeaders(),
           json={"PlayFabId": current_player_id, "Data": {"DailyLogin": datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=timezone.utc).isoformat()}}
       )
   return "", 200

@app.route("/api/ShouldUserAutomutePlayer", methods=["POST", "GET"])
def shoulduserautomuteplayer():
   return jsonify(muteCache)

@app.route("/api/ValidateMovement", methods=["POST"])
@rate_limit(max_requests=60, window_seconds=60)
def validate_movement():
   data = request.get_json()
   playfab_id = data.get("playFabId")
   position = data.get("position", {})
   arm_length = data.get("armLength", 0)
   platform = data.get("platform", "")
   device_model = data.get("deviceModel", "")
   user_agent = request.headers.get("User-Agent", "")
   timestamp = data.get("timestamp", time.time())
   client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
   if client_ip and "," in client_ip:
       client_ip = client_ip.split(",")[0].strip()
   if not playfab_id:
       return jsonify({"valid": False, "warning": True, "reason": "missing_playfab_id"}), 403
   violations = []
   if detect_speed_hack(playfab_id, position, timestamp):
       violations.append("speed_hack")
   if detect_long_arms(playfab_id, arm_length):
       violations.append("long_arms")
   trust_score = calculate_trust_score(playfab_id)
   ingame_name = get_ingame_name(playfab_id)
   response = {
       "valid": len(violations) == 0, "violations": violations,
       "trustScore": trust_score, "warning": trust_score < 50
   }
   pos_str = f"x={position.get('x', 0):.2f}, y={position.get('y', 0):.2f}, z={position.get('z', 0):.2f}"
   if violations:
       send_webhook({
           "title": "Movement Violation Detected", "color": 0xFF0000,
           "fields": [
               {"name": "PlayFab ID", "value": f"```{playfab_id}```", "inline": True},
               {"name": "In-Game Name", "value": f"```{ingame_name}```", "inline": True},
               {"name": "IP", "value": f"```{client_ip}```", "inline": True},
               {"name": "Violations", "value": f"```{', '.join(violations)}```", "inline": False},
               {"name": "Position", "value": f"```{pos_str}```", "inline": True},
               {"name": "Arm Length", "value": f"```{arm_length:.3f} units```", "inline": True},
               {"name": "Trust Score", "value": f"```{trust_score}```", "inline": True},
           ],
           "timestamp": datetime.now().isoformat(),
       })
   if trust_score < 30:
       response["suggestBan"] = True
       response["banReason"] = f"Low trust score: {trust_score}"
   return jsonify(response), 200

@app.route("/api/ReportViolation", methods=["POST"])
@rate_limit(max_requests=10, window_seconds=60)
def report_violation():
   data = request.get_json()
   playfab_id = data.get("playFabId")
   reporter_id = data.get("reporterId")
   violation_type = data.get("violationType")
   reason = data.get("reason", "No reason provided")
   severity = data.get("severity", "MEDIUM")
   evidence = data.get("evidence", {})
   client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
   if client_ip and "," in client_ip:
       client_ip = client_ip.split(",")[0].strip()
   if not playfab_id or not violation_type:
       return jsonify({"error": "Missing required fields"}), 400
   reported_name = get_ingame_name(playfab_id)
   reporter_name = get_ingame_name(reporter_id) if reporter_id else "N/A"
   add_violation(playfab_id, violation_type, reason, severity, evidence)
   trust_score = calculate_trust_score(playfab_id)
   color_map = {"CRITICAL": 0x8B0000, "HIGH": 0xFF0000, "MEDIUM": 0xFF6600, "LOW": 0xFFFF00}
   embed_color = color_map.get(severity.upper(), 0xFF6600)
   send_webhook({
       "title": f"Violation Reported: {violation_type}", "color": embed_color,
       "fields": [
           {"name": "Reported PlayFab ID", "value": f"```{playfab_id}```", "inline": True},
           {"name": "Reported In-Game Name", "value": f"```{reported_name}```", "inline": True},
           {"name": "Reporter PlayFab ID", "value": f"```{reporter_id or 'N/A'}```", "inline": True},
           {"name": "Reporter In-Game Name", "value": f"```{reporter_name}```", "inline": True},
           {"name": "IP", "value": f"```{client_ip}```", "inline": True},
           {"name": "Violation Type", "value": f"```{violation_type}```", "inline": True},
           {"name": "Severity", "value": f"```{severity}```", "inline": True},
           {"name": "Trust Score", "value": f"```{trust_score}```", "inline": True},
           {"name": "Total Violations", "value": f"```{len(violation_cache.get(playfab_id, []))}```", "inline": True},
           {"name": "Reason", "value": f"```{reason}```", "inline": False},
       ],
       "timestamp": datetime.now().isoformat(),
   }, REPORT_WEBHOOK_URL)
   return jsonify({"success": True, "trustScore": trust_score, "reportedName": reported_name}), 200

@app.route("/api/GetTrustScore", methods=["POST"])
@rate_limit(max_requests=30, window_seconds=60)
def get_trust_score():
   data = request.get_json()
   playfab_id = data.get("playFabId")
   client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
   if client_ip and "," in client_ip:
       client_ip = client_ip.split(",")[0].strip()
   if not playfab_id:
       return jsonify({"error": "Missing playFabId"}), 400
   trust_score = calculate_trust_score(playfab_id)
   ingame_name = get_ingame_name(playfab_id)
   violation_count = len(violation_cache.get(playfab_id, []))
   recent_viols = violation_cache.get(playfab_id, [])[-3:]
   recent_str = ", ".join([v.get("type", "?") for v in recent_viols]) if recent_viols else "None"
   color = 0x00FF00 if trust_score >= 70 else (0xFF6600 if trust_score >= 40 else 0xFF0000)
   send_webhook({
       "title": "Trust Score Lookup", "color": color,
       "fields": [
           {"name": "PlayFab ID", "value": f"```{playfab_id}```", "inline": True},
           {"name": "In-Game Name", "value": f"```{ingame_name}```", "inline": True},
           {"name": "IP", "value": f"```{client_ip}```", "inline": True},
           {"name": "Trust Score", "value": f"```{trust_score}```", "inline": True},
           {"name": "Total Violations", "value": f"```{violation_count}```", "inline": True},
           {"name": "Recent Violations", "value": f"```{recent_str}```", "inline": False}
       ],
       "timestamp": datetime.now().isoformat(),
   })
   return jsonify({"playFabId": playfab_id, "ingameName": ingame_name, "trustScore": trust_score, "violationCount": violation_count}), 200

@app.route("/api/VerifySession", methods=["POST"])
@rate_limit(max_requests=30, window_seconds=60)
def verify_session():
   data = request.get_json()
   token = data.get("sessionToken")
   if not token:
       return jsonify({"valid": False, "reason": "No token provided"}), 400
   playfab_id = verify_session_token(token)
   if playfab_id:
       trust_score = calculate_trust_score(playfab_id)
       ingame_name = get_ingame_name(playfab_id)
       return jsonify({"valid": True, "playFabId": playfab_id, "ingameName": ingame_name}), 200
   else:
       return jsonify({"valid": False, "reason": "Invalid or expired token"}), 401

@app.route("/api/VerifyNativeLib", methods=["POST", "GET"])
@rate_limit(max_requests=10, window_seconds=60)
def verify_native_lib():
   client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
   if client_ip and "," in client_ip:
       client_ip = client_ip.split(",")[0].strip()
   data = request.get_json() if request.is_json else {}
   lib_signature = data.get("signature", "")
   lib_hash = data.get("hash", "")
   lib_version = data.get("version", "unknown")
   playfab_id = data.get("playFabId", "N/A")
   ingame_name = get_ingame_name(playfab_id)
   is_valid = bool(lib_signature) and bool(lib_hash) and len(lib_signature) > 10
   if not is_valid:
       send_webhook([{
           "title": "Native Anti-Cheat Library Verification FAILED", "color": 0xFF0000,
           "fields": [
               {"name": "PlayFab ID", "value": f"```{playfab_id}```", "inline": True},
               {"name": "In-Game Name", "value": f"```{ingame_name}```", "inline": True},
               {"name": "IP", "value": f"```{client_ip}```", "inline": True},
               {"name": "Status", "value": "```FAILED - Access Denied```", "inline": False},
           ],
       }], ALERT_WEBHOOK_URL)
       return jsonify({"verified": False, "message": "Native library verification failed \u2013 access denied"}), 403
   send_webhook([{
       "title": "Native Anti-Cheat Library Verified", "color": 0x00FF00,
       "fields": [
           {"name": "PlayFab ID", "value": f"```{playfab_id}```", "inline": True},
           {"name": "Status", "value": "```PASSED - Access Granted```", "inline": False}
       ],
   }], ALERT_WEBHOOK_URL)
   return jsonify({"verified": True, "message": "Native library verified", "timestamp": datetime.now().isoformat()}), 200

# ---------- Admin Endpoints ----------
@app.route("/api/admin/ban", methods=["POST"])
@rate_limit(max_requests=30, window_seconds=60)
@require_admin
def admin_ban():
   data = request.get_json()
   target_id = data.get("playFabId")
   reason = data.get("reason", "Banned by admin")
   duration = data.get("duration", "Permanent")
   if not target_id:
       return jsonify({"error": "Missing playFabId"}), 400
   target_name = get_ingame_name(target_id)
   duration_hours = 0 if duration == "Permanent" else int(duration)
   ban_request = requests.post(
       url=f"https://{settings.TitleId}.playfabapi.com/Admin/BanUsers",
       json={"Bans": [{"PlayFabId": target_id, "DurationInHours": duration_hours, "Reason": reason}]},
       headers=settings.GetAuthHeaders()
   )
   if ban_request.status_code == 200:
       is_permanent = (duration == "Permanent")
       device_ban_result = None
       if is_permanent and settings.EnableMetaDeviceBan:
           unique_id = get_cached_unique_id(target_id)
           if unique_id:
               device_ban_result = meta_device_ban(unique_id=unique_id, is_banned=True, remaining_minutes=settings.DefaultDeviceBanMinutes)
               if device_ban_result and device_ban_result.get("ban_id"):
                   playfabCache.setdefault(target_id, {})["MetaDeviceBanId"] = device_ban_result["ban_id"]
       add_violation(target_id, "ADMIN_BAN", reason, "CRITICAL")
       send_alert("Admin Ban Executed", [
           {"name": "PlayFab ID", "value": f"```{target_id}```", "inline": True},
           {"name": "In-Game Name", "value": f"```{target_name}```", "inline": True},
           {"name": "Duration", "value": f"```{str(duration)}```", "inline": True},
           {"name": "Reason", "value": f"```{reason}```", "inline": False}
       ], 0x8B0000)
       return jsonify({"success": True, "deviceBanId": device_ban_result.get("ban_id") if device_ban_result else None}), 200
   return jsonify({"success": False, "error": ban_request.text}), 500

@app.route("/api/admin/unblock", methods=["POST"])
@rate_limit(max_requests=30, window_seconds=60)
@require_admin
def admin_unblock():
   data = request.get_json()
   target_id = data.get("playFabId")
   admin_note = data.get("note", "Manually unblocked by admin")
   if not target_id:
       return jsonify({"error": "Missing playFabId"}), 400
   ingame_name = get_ingame_name(target_id)
   resolved_oculus = _full_unblock(target_id)
   try:
       requests.post(
           url=f"https://{settings.TitleId}.playfabapi.com/Admin/RevokeAllBansForUser",
           json={"PlayFabId": target_id}, headers=settings.GetAuthHeaders(), timeout=8
       )
   except Exception as e:
       print(f"[Unblock] RevokeAllBansForUser error: {e}")
   send_alert("Player Auth Unblocked", [
       {"name": "PlayFab ID", "value": f"```{target_id}```", "inline": True},
       {"name": "Oculus ID", "value": f"```{resolved_oculus or 'unknown'}```", "inline": True},
       {"name": "In-Game Name", "value": f"```{ingame_name}```", "inline": True},
       {"name": "Admin Note", "value": f"```{admin_note}```", "inline": False}
   ], 0x00FF00)
   return jsonify({"success": True, "playFabId": target_id, "oculusId": resolved_oculus, "trustReset": True, "heartbeatReset": True, "sessionDropped": True}), 200

@app.route("/api/admin/unban-list", methods=["POST"])
@rate_limit(max_requests=3, window_seconds=60)
@require_admin
def admin_unban_list():
   data = request.get_json() or {}
   ids = data.get("playFabIds") or []
   if not isinstance(ids, list) or not ids:
       return jsonify({"error": "provide playFabIds: [ ... ]"}), 400
   revoked, no_ban, errors = [], [], []
   for pid in ids:
       pid = str(pid).strip()
       if not pid or pid == "N/A":
           continue
       try:
           _full_unblock(pid)
       except Exception as e:
           print(f"[UnbanList] full_unblock {pid}: {e}")
       try:
           r = requests.post(url=f"https://{settings.TitleId}.playfabapi.com/Admin/RevokeAllBansForUser", json={"PlayFabId": pid}, headers=settings.GetAuthHeaders(), timeout=8)
           if r.status_code == 200:
               bans = r.json().get("data", {}).get("BanData", [])
               (revoked if bans else no_ban).append(pid)
           else:
               errors.append({"id": pid, "code": r.status_code})
       except Exception as e:
           errors.append({"id": pid, "error": str(e)})
   send_alert("Unban List Executed", [
       {"name": "Submitted", "value": f"```{len(ids)}```", "inline": True},
       {"name": "Bans revoked", "value": f"```{len(revoked)}```", "inline": True},
       {"name": "No ban / errors", "value": f"```{len(no_ban)} / {len(errors)}```", "inline": True},
   ], 0x00FF00)
   return jsonify({"success": True, "submitted": len(ids), "revoked_count": len(revoked), "no_ban_count": len(no_ban), "error_count": len(errors), "errors": errors}), 200

@app.route("/api/admin/revoke-all-playfab-bans", methods=["POST"])
@rate_limit(max_requests=3, window_seconds=60)
@require_admin
def admin_revoke_all_playfab_bans():
   data = request.get_json() or {}
   if not bool(data.get("confirm", False)):
       return jsonify({"error": "Refused: requires 'confirm': true"}), 400
   ids = set(blocked_playfab_ids.keys())
   bcol = _get_blocked_col()
   if bcol is not None:
       try:
           for doc in bcol.find({}, {"playFabId": 1}):
               if doc.get("playFabId"):
                   ids.add(doc["playFabId"])
       except Exception as e:
           print(f"[RevokeAll] blocked scan failed: {e}")
   vcol = _get_violation_col()
   if vcol is not None:
       try:
           for doc in vcol.find({}, {"playFabId": 1}):
               if doc.get("playFabId"):
                   ids.add(doc["playFabId"])
       except Exception as e:
           print(f"[RevokeAll] violations scan failed: {e}")
   ids = list(ids)
   revoked, no_ban, errors = [], [], []
   for pid in ids:
       try:
           r = requests.post(url=f"https://{settings.TitleId}.playfabapi.com/Admin/RevokeAllBansForUser", json={"PlayFabId": pid}, headers=settings.GetAuthHeaders(), timeout=8)
           if r.status_code == 200:
               bans = r.json().get("data", {}).get("BanData", [])
               (revoked if bans else no_ban).append(pid)
           else:
               errors.append({"id": pid, "code": r.status_code})
       except Exception as e:
           errors.append({"id": pid, "error": str(e)})
   send_alert("Mass PlayFab Ban Revoke", [
       {"name": "Scanned", "value": f"```{len(ids)}```", "inline": True},
       {"name": "Had bans revoked", "value": f"```{len(revoked)}```", "inline": True},
       {"name": "No ban / errors", "value": f"```{len(no_ban)} / {len(errors)}```", "inline": True},
   ], 0x00FF00)
   return jsonify({"success": True, "scanned": len(ids), "revoked_count": len(revoked), "no_ban_count": len(no_ban), "error_count": len(errors), "revoked": revoked, "errors": errors}), 200

@app.route("/api/admin/clear-all-blocks", methods=["POST"])
@rate_limit(max_requests=5, window_seconds=60)
@require_admin
def admin_clear_all_blocks():
   data = request.get_json() or {}
   filter_type = data.get("type")
   confirm = bool(data.get("confirm", False))
   note = data.get("note", "Manual mass clear")
   if not filter_type and not confirm:
       return jsonify({"error": "Refused: mass clear requires 'confirm': true, or provide a 'type' filter", "example": {"confirm": True, "note": "clearing all FP heartbeat blocks"}}), 400
   targets = set()
   col = _get_blocked_col()
   if filter_type:
       for pid, info in blocked_playfab_ids.items():
           if info.get("type") == filter_type:
               targets.add(pid)
       if col is not None:
           try:
               for doc in col.find({"type": filter_type}, {"playFabId": 1}):
                   targets.add(doc["playFabId"])
           except Exception as e:
               print(f"[ClearAll] Mongo scan failed: {e}")
   else:
       targets.update(blocked_playfab_ids.keys())
       if col is not None:
           try:
               for doc in col.find({}, {"playFabId": 1}):
                   targets.add(doc["playFabId"])
           except Exception as e:
               print(f"[ClearAll] Mongo scan failed: {e}")
   targets = list(targets)
   cleared_count = 0
   for pid in targets:
       _full_unblock(pid)
       cleared_count += 1
       try:
           requests.post(url=f"https://{settings.TitleId}.playfabapi.com/Admin/RevokeAllBansForUser", json={"PlayFabId": pid}, headers=settings.GetAuthHeaders(), timeout=5)
       except Exception as e:
           print(f"[ClearAll] RevokeAllBans failed for {pid}: {e}")
   if col is not None:
       try:
           if filter_type:
               col.delete_many({"type": filter_type})
           else:
               col.delete_many({})
       except Exception as e:
           print(f"[ClearAll] Mongo bulk delete failed: {e}")
   _hb_not_ready_attempts.clear()
   send_alert("ADMIN - Mass Block Clear", [
       {"name": "Cleared Count", "value": f"```{cleared_count}```", "inline": True},
       {"name": "Filter Type", "value": f"```{filter_type or 'ALL'}```", "inline": True},
       {"name": "Admin Note", "value": f"```{note}```", "inline": False},
   ], 0x00FF00)
   print(f"[ClearAll] Cleared {cleared_count} blocks (type={filter_type or 'ALL'})")
   return jsonify({"success": True, "cleared": cleared_count, "filterType": filter_type or "ALL", "clearedPlayFabIds": targets}), 200

@app.route("/api/admin/list-blocks", methods=["GET"])
@rate_limit(max_requests=30, window_seconds=60)
@require_admin
def admin_list_blocks():
   blocks = []
   for pid, info in blocked_playfab_ids.items():
       if not _is_block_expired(info):
           blocks.append({"playFabId": pid, "oculusId": info.get("oculusId"), "type": info.get("type"), "reason": info.get("reason"), "timestamp": info.get("timestamp")})
   return jsonify({"count": len(blocks), "blocks": blocks}), 200

@app.route("/api/admin/hwid-ban", methods=["POST"])
@rate_limit(max_requests=30, window_seconds=60)
@require_admin
def admin_hwid_ban():
   data = request.get_json()
   hwid = data.get("hwid")
   reason = data.get("reason", "HWID banned by admin")
   if not hwid:
       return jsonify({"error": "Missing hwid"}), 400
   banned_hwids.add(hwid)
   send_alert("HWID Ban Executed", [{"name": "HWID", "value": hwid, "inline": True}], 0x8B0000)
   return jsonify({"success": True}), 200

@app.route("/api/admin/device-ban", methods=["POST"])
@rate_limit(max_requests=30, window_seconds=60)
@require_admin
def admin_device_ban():
   data = request.get_json() or {}
   target_id = data.get("playFabId")
   unique_id = data.get("uniqueId") or (get_cached_unique_id(target_id) if target_id else None)
   ban_id = data.get("banId") or (get_cached_ban_id(target_id) if target_id else None)
   is_banned = data.get("isBanned", True)
   remaining_minutes = data.get("remainingMinutes", settings.DefaultDeviceBanMinutes)
   reason = data.get("reason", "Device banned by admin")
   if not unique_id and not ban_id:
       return jsonify({"error": "Missing uniqueId/banId"}), 400
   result = meta_device_ban(unique_id=unique_id, ban_id=ban_id, is_banned=is_banned, remaining_minutes=remaining_minutes)
   if not result:
       return jsonify({"success": False}), 500
   if target_id and result.get("ban_id"):
       playfabCache.setdefault(target_id, {})["MetaDeviceBanId"] = result["ban_id"]
   return jsonify({"success": True, "banId": result.get("ban_id")}), 200

@app.route("/api/admin/ip-ban", methods=["POST"])
@rate_limit(max_requests=30, window_seconds=60)
@require_admin
def admin_ip_ban():
   data = request.get_json()
   ip = data.get("ip")
   reason = data.get("reason", "IP banned by admin")
   if not ip:
       return jsonify({"error": "Missing ip"}), 400
   banned_ips.add(ip)
   send_alert("IP Ban Executed", [{"name": "IP", "value": ip, "inline": True}], 0x8B0000)
   return jsonify({"success": True}), 200

@app.route("/api/admin/stats", methods=["GET"])
@rate_limit(max_requests=30, window_seconds=60)
@require_admin
def admin_stats():
   client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
   if client_ip and "," in client_ip:
       client_ip = client_ip.split(",")[0].strip()
   all_violations = [v for vs in violation_cache.values() for v in vs]
   total_viols = len(all_violations)
   unique_players = len(violation_cache)
   banned_hw = len(banned_hwids)
   banned_ip_count = len(banned_ips)
   avg_trust = round(sum(trust_scores.values()) / len(trust_scores), 1) if trust_scores else 100
   active_count = len(active_sessions)
   blocked_count = len(blocked_playfab_ids)
   send_webhook({
       "title": "Admin Stats Requested", "color": 0x5865F2,
       "fields": [
           {"name": "Requested By IP", "value": f"```{client_ip}```", "inline": True},
           {"name": "Active Sessions", "value": f"```{active_count}```", "inline": True},
           {"name": "Blocked Players", "value": f"```{blocked_count}```", "inline": True},
           {"name": "Total Violations", "value": f"```{total_viols}```", "inline": True},
           {"name": "Avg Trust Score", "value": f"```{avg_trust}```", "inline": True},
       ],
       "timestamp": datetime.now().isoformat(),
   })
   return jsonify({"totalViolations": total_viols, "uniquePlayersWithViolations": unique_players, "bannedHWIDs": banned_hw, "bannedIPs": banned_ip_count, "averageTrustScore": avg_trust, "activeSessions": active_count, "blockedPlayers": blocked_count}), 200

@app.route("/api/admin/local-device-ban", methods=["POST"])
@rate_limit(max_requests=30, window_seconds=60)
@require_admin
def admin_local_device_ban():
   data = request.get_json() or {}
   device_id = data.get("deviceId")
   reason = data.get("reason", "Device banned by admin")
   if not device_id:
       return jsonify({"error": "Missing deviceId"}), 400
   add_device_ban(device_id, reason)
   return jsonify({"success": True, "deviceId": device_id}), 200

@app.route("/api/admin/local-device-unban", methods=["POST"])
@rate_limit(max_requests=30, window_seconds=60)
@require_admin
def admin_local_device_unban():
   data = request.get_json() or {}
   device_id = data.get("deviceId")
   if not device_id:
       return jsonify({"error": "Missing deviceId"}), 400
   remove_device_ban(device_id)
   return jsonify({"success": True, "deviceId": device_id}), 200

@app.route("/api/admin/local-device-bans", methods=["GET"])
@rate_limit(max_requests=30, window_seconds=60)
@require_admin
def admin_list_device_bans():
   return jsonify({"bans": list_device_bans()}), 200

# ---------- Report Spam Check ----------
REPORT_SPAM_MAX = 7
REPORT_SPAM_WINDOW = 20
REPORT_SPAM_BAN_HOURS = 1

_report_spam_col = None

def _get_report_spam_col():
   global _report_spam_col, _mongo_client
   if _report_spam_col is not None:
       return _report_spam_col
   if _mongo_client is None:
       if not _MONGO_URI:
           return None
       try:
           _mongo_client = MongoClient(_MONGO_URI, serverSelectionTimeoutMS=5000)
       except:
           return None
   _report_spam_col = _mongo_client["WIFI TAG"]["report_spam"]
   try:
       _report_spam_col.create_index("reporterId", unique=True)
   except:
       pass
   return _report_spam_col

@app.route("/api/ReportSpamCheck", methods=["POST"])
@rate_limit(max_requests=60, window_seconds=60)
def report_spam_check():
   data = request.get_json() or {}
   reporter_id = data.get("reporterId")
   reported_id = data.get("reportedId")
   reporter_name = data.get("reporterName", "N/A")
   reported_name = data.get("reportedName", "N/A")
   reason = data.get("reason", 0)
   game_id = data.get("gameId", "N/A")

   if not reporter_id:
       return jsonify({"blocked": False}), 200

   now = time.time()
   col = _get_report_spam_col()

   print(f"[ReportSpam] reporter={reporter_id} reported={reported_id} mongo={'connected' if col else 'NONE'}")

   if col is None:
       print("[ReportSpam] MongoDB not connected - cannot track spam")
       return jsonify({"blocked": False}), 200

   doc = col.find_one({"reporterId": reporter_id})
   if not doc:
       col.insert_one({"reporterId": reporter_id, "timestamps": [now]})
       print(f"[ReportSpam] First report from {reporter_id} - count=1")
       return jsonify({"blocked": False, "count": 1}), 200

   timestamps = doc.get("timestamps", [])
   recent = [ts for ts in timestamps if now - ts < REPORT_SPAM_WINDOW]
   recent.append(now)

   col.update_one(
       {"reporterId": reporter_id},
       {"$set": {"timestamps": recent}}
   )

   print(f"[ReportSpam] reporter={reporter_id} count={len(recent)}/{REPORT_SPAM_MAX} window={REPORT_SPAM_WINDOW}s")

   if len(recent) >= REPORT_SPAM_MAX:
       try:
           requests.post(
               url=f"https://{settings.TitleId}.playfabapi.com/Admin/BanUsers",
               json={"Bans": [{"PlayFabId": reporter_id, "DurationInHours": REPORT_SPAM_BAN_HOURS,
                      "Reason": "SPAM REPORTING - IF THIS WAS A FALSE BAN, PLEASE APPEAL AT discord.gg/bwZ3P84EFw"}]},
               headers=settings.GetAuthHeaders(), timeout=8
           )
       except Exception as e:
           print(f"[ReportSpam] Ban failed: {e}")

       col.update_one({"reporterId": reporter_id}, {"$set": {"timestamps": []}})

       send_alert("REPORTER BANNED - SPAM REPORTING", [
           {"name": "Reporter ID", "value": f"```{reporter_id}```", "inline": True},
           {"name": "Reporter Name", "value": f"```{reporter_name}```", "inline": True},
           {"name": "Reports in Window", "value": f"```{len(recent)} in {REPORT_SPAM_WINDOW}s```", "inline": True},
           {"name": "Last Reported", "value": f"```{reported_name} ({reported_id})```", "inline": True},
           {"name": "Ban Duration", "value": f"```{REPORT_SPAM_BAN_HOURS} hour(s)```", "inline": True},
           {"name": "Game ID", "value": f"```{game_id}```", "inline": True},
       ], 0xFF0000)

       return jsonify({"blocked": True, "count": len(recent)}), 200

   return jsonify({"blocked": False, "count": len(recent)}), 200

# ---------- Startup ----------
def start_rate_limit_cleanup():
   while True:
       time.sleep(300)
       _cleanup_rate_limits()

_rate_cleanup_thread = threading.Thread(target=start_rate_limit_cleanup, daemon=True)
_rate_cleanup_thread.start()

load_blocks()

if __name__ == "__main__":
   port = int(os.getenv("PORT", 8080))
   app.run(host="0.0.0.0", port=port)
