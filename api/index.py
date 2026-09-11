import requests
import random
import time
import hashlib
import hmac
from flask import Flask, jsonify, request
from threading import Lock
from pymongo import MongoClient
from datetime import datetime, timezone

class GameInfo:
    def __init__(self):
        self.TitleId: str = "F8C32"
        self.SecretKey: str = "TTY48MZYQJWMSHDTWKUDZWICWZCCRR5BZ57MHK1XOHHOFP73D5"
        self.ApiKey: str = "OC|1250381298163039|bcc3376df25a224258c8911994a1e6bb"
        self.DiscordWebhookUrl: str = "https://discord.com/api/webhooks/1547844193144274964/YRt26ivvIASxWUsZ_-29E2nKcANTg4xVXsI39tTZGhDrutaylCXE7OOiYrEcLTHK2KBw"
        self.RequestSignatureSecret: str = "9f7c2e1a8b4d6f0c3e5a7b9d1f4c8e2a6b0d3f7c1e5a9b2d"
        self.MongoUri: str = "mongodb+srv://99978:osLYa9p3gCLT11vi@pp.mwblhhy.mongodb.net/pp?"
        self.DbName: str = "pp"

    def get_auth_headers(self):
        return {"content-type": "application/json", "X-SecretKey": self.SecretKey}


settings = GameInfo()
app = Flask(__name__)

mongo_client = MongoClient(settings.MongoUri)
db = mongo_client[settings.DbName]
users_collection = db["users"]
nonces_collection = db["nonces"]
auth_logs_collection = db["auth_logs"]

nonces_collection.create_index("created_at", expireAfterSeconds=300)
nonces_collection.create_index("nonce", unique=True)
users_collection.create_index("oculus_id", unique=True)
users_collection.create_index("playfab_id", unique=True)

nonce_lock = Lock()
ip_request_log = {}


def get_client_ip():
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        return request.environ['REMOTE_ADDR']
    else:
        return request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()


def validate_ip(client_ip: str):
    now = time.time()
    window = 60
    max_requests = 30

    if client_ip not in ip_request_log:
        ip_request_log[client_ip] = []

    ip_request_log[client_ip] = [t for t in ip_request_log[client_ip] if now - t < window]
    ip_request_log[client_ip].append(now)

    if len(ip_request_log[client_ip]) > max_requests:
        return False

    return True


def validate_request_signature(rjson: dict, signature: str):
    if not signature:
        return False

    sorted_keys = sorted(rjson.keys())
    payload = "&".join(f"{k}={rjson[k]}" for k in sorted_keys)
    expected = hmac.new(settings.RequestSignatureSecret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def validate_session_ticket(session_ticket: str):
    if not session_ticket:
        return False, "Missing session ticket"

    parts = session_ticket.split('-')
    if len(parts) < 3:
        return False, "Malformed session ticket"

    playfab_id = parts[0]
    if len(playfab_id) != 16:
        return False, "Invalid player ID in session ticket"

    req = requests.post(
        url=f"https://{settings.TitleId}.playfabapi.com/Server/AuthenticateSessionTicket",
        json={"SessionTicket": session_ticket},
        headers=settings.get_auth_headers()
    )

    if req.status_code != 200:
        return False, "Session ticket validation failed"

    data = req.json().get("data", {})
    is_expired = data.get("IsSessionTicketExpired", True)

    if is_expired:
        return False, "Session ticket is expired"

    return True, None


def get_oculus_nonce_valid(nonce: str, oculus_id: str):
    try:
        req = requests.post(
            url="https://graph.oculus.com/user_nonce_validate",
            data={
                "nonce": nonce,
                "user_id": oculus_id,
                "access_token": settings.ApiKey
            },
            timeout=5
        )
    except requests.RequestException:
        return False

    if req.status_code != 200:
        return False

    try:
        data = req.json()
    except ValueError:
        return False

    if data.get("is_valid") is not True:
        return False

    returned_user_id = data.get("user_id")
    if returned_user_id is not None and str(returned_user_id) != str(oculus_id):
        return False

    return True


def validate_and_bind_nonce(nonce: str, oculus_id: str):
    if not nonce or not oculus_id:
        return False, "Missing nonce or Oculus ID"

    with nonce_lock:
        existing = nonces_collection.find_one({"nonce": nonce})
        if existing:
            if existing["oculus_id"] != oculus_id:
                return False, "Nonce bound to different Oculus ID"
            return False, "Nonce already used"

    if not get_oculus_nonce_valid(nonce, oculus_id):
        return False, "Invalid nonce"

    with nonce_lock:
        existing = nonces_collection.find_one({"nonce": nonce})
        if existing:
            if existing["oculus_id"] != oculus_id:
                return False, "Nonce bound to different Oculus ID"
            return False, "Nonce already used"

        nonces_collection.insert_one({
            "nonce": nonce,
            "oculus_id": oculus_id,
            "created_at": datetime.now(timezone.utc)
        })

    return True, None


def get_org_scoped_id(oculus_id: str):
    url = f"https://graph.oculus.com/{oculus_id}?access_token={settings.ApiKey}&fields=org_scoped_id"
    res = requests.get(url=url, headers={"Content-Type": "application/json"})
    if res.status_code == 200:
        return res.json().get("org_scoped_id")
    return None


def validate_meta_alias(oculus_id: str):
    try:
        url = f"https://graph.oculus.com/{oculus_id}?access_token={settings.ApiKey}&fields=alias"
        res = requests.get(url=url, headers={"Content-Type": "application/json"}, timeout=5)
    except requests.RequestException:
        return False, None

    if res.status_code != 200:
        return False, None

    try:
        data = res.json()
    except ValueError:
        return False, None

    alias = data.get("alias")
    if not alias or len(alias.strip()) == 0:
        return False, None

    return True, alias


def store_user(oculus_id: str, playfab_id: str, org_scoped_id: str, meta_alias: str, client_ip: str, custom_id: str = None):
    users_collection.update_one(
        {"oculus_id": oculus_id},
        {
            "$set": {
                "playfab_id": playfab_id,
                "org_scoped_id": org_scoped_id,
                "meta_alias": meta_alias,
                "custom_id": custom_id,
                "last_ip": client_ip,
                "last_login": datetime.now(timezone.utc),
                "playfab_authed": True
            },
            "$setOnInsert": {
                "first_seen": datetime.now(timezone.utc)
            }
        },
        upsert=True
    )


def log_auth_attempt(success: bool, client_ip: str, oculus_id: str = None, playfab_id: str = None, error_message: str = None):
    auth_logs_collection.insert_one({
        "success": success,
        "ip": client_ip,
        "oculus_id": oculus_id,
        "playfab_id": playfab_id,
        "error": error_message,
        "timestamp": datetime.now(timezone.utc)
    })


def send_auth_webhook(success: bool, player_ip: str, custom_id: str = None, playfab_id: str = None, oculus_id: str = None, error_message: str = None):
    try:
        if success:
            embed_data = {
                "content": None,
                "embeds": [{
                    "color": 65280,
                    "fields": [{
                        "name": "NORMAL FELLA LOGGED IN!",
                        "value": f"```ini\n[ Player's IP ]: {request.headers.get('X-Real-IP') or player_ip}\n[Custom ID]: {custom_id or 'N/A'}\n[Player ID]: {playfab_id or 'N/A'}\n[Orgscoped ID]: {oculus_id or 'N/A'}```"
                    }],
                    "author": {"name": "Sigmer Auth"}
                }]
            }
        else:
            embed_data = {
                "content": None,
                "embeds": [{
                    "color": 16711680,
                    "fields": [{
                        "name": "INVALID FELLA TRIED TO AUTH!",
                        "value": f"```ini\n[ Player's IP ]: {request.headers.get('X-Real-IP') or player_ip}\n[Custom ID]: {custom_id or 'N/A'}\n[Orgscoped ID]: {oculus_id or 'N/A'}\n[Error]: {error_message or 'Unknown Error'}```"
                    }],
                    "author": {"name": "Sigmer Auth"}
                }]
            }

        requests.post(settings.DiscordWebhookUrl, json=embed_data, timeout=5)
    except Exception as e:
        print(f"Failed to send webhook: {e}")


def auth_fail(client_ip, error_msg, oculus_id=None, custom_id=None, status=403, error_code="Forbidden"):
    send_auth_webhook(False, client_ip, custom_id=custom_id, oculus_id=oculus_id, error_message=error_msg)
    log_auth_attempt(False, client_ip, oculus_id=oculus_id, error_message=error_msg)
    return jsonify({"Message": error_msg, "Error": error_code}), status


@app.route("/", methods=["POST", "GET"])
def main():
    return """
        <html>
            <head>
                <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;700&display=swap" rel="stylesheet">
            </head>
            <body style="font-family: 'Inter', sans-serif;">
                <h1 style="color: red; font-size: 30px;">
                    WHAT DA SIGMER
                </h1>
            </body>
        </html>
    """


@app.route("/api/PlayFabAuthentication", methods=["POST"])
def playfab_authentication():
    rjson = request.get_json()
    client_ip = get_client_ip()

    if not validate_ip(client_ip):
        return auth_fail(client_ip, "Rate limited", error_code="Forbidden-RateLimited", status=429)

    signature = request.headers.get("X-Request-Signature")
    if not validate_request_signature(rjson, signature):
        return auth_fail(client_ip, "Invalid request signature", error_code="Forbidden-BadSignature")

    required_fields = ["Nonce", "AppId", "Platform", "OculusId"]
    missing_fields = [f for f in required_fields if not rjson.get(f)]
    if missing_fields:
        return auth_fail(client_ip, f"Missing parameter(s): {', '.join(missing_fields)}", error_code=f"BadRequest-No{missing_fields[0]}", status=401)

    if rjson.get("AppId") != settings.TitleId:
        return auth_fail(client_ip, "App ID mismatch", oculus_id=rjson.get("OculusId"), error_code="BadRequest-AppIdMismatch", status=400)

    nonce = rjson.get("Nonce")
    oculus_id = rjson.get("OculusId")

    nonce_valid, nonce_error = validate_and_bind_nonce(nonce, oculus_id)
    if not nonce_valid:
        error_code = "Forbidden-NonceReplay" if "already used" in nonce_error.lower() else "Forbidden-BadNonce"
        return auth_fail(client_ip, nonce_error, oculus_id=oculus_id, error_code=error_code)

    alias_valid, meta_alias = validate_meta_alias(oculus_id)
    if not alias_valid:
        return auth_fail(client_ip, "Failed to verify Meta alias", oculus_id=oculus_id, error_code="BadRequest-InvalidAlias", status=400)

    org_scoped_id = get_org_scoped_id(oculus_id)
    if not org_scoped_id:
        return auth_fail(client_ip, "Invalid Oculus ID", oculus_id=oculus_id, error_code="BadRequest-InvalidOculusId", status=400)

    login_request = requests.post(
        url=f"https://{settings.TitleId}.playfabapi.com/Server/LoginWithServerCustomId",
        json={"ServerCustomId": "OCULUS" + oculus_id, "CreateAccount": True},
        headers=settings.get_auth_headers(),
    )

    if login_request.status_code == 200:
        data = login_request.json().get("data")
        session_ticket = data.get("SessionTicket")
        entity_token = data.get("EntityToken").get("EntityToken")
        playfab_id = data.get("PlayFabId")
        entity_type = data.get("EntityToken").get("Entity").get("Type")
        entity_id = data.get("EntityToken").get("Entity").get("Id")

        ticket_valid, ticket_error = validate_session_ticket(session_ticket)
        if not ticket_valid:
            return auth_fail(client_ip, f"Session ticket issue: {ticket_error}", oculus_id=oculus_id, error_code="Forbidden-BadSessionTicket")

        custom_id = rjson.get("CustomId")

        requests.post(
            url=f"https://{settings.TitleId}.playfabapi.com/Server/LinkServerCustomId",
            json={"ForceLink": True, "PlayFabId": playfab_id, "ServerCustomId": custom_id},
            headers=settings.get_auth_headers(),
        )

        store_user(oculus_id, playfab_id, org_scoped_id, meta_alias, client_ip, custom_id)
        log_auth_attempt(True, client_ip, oculus_id=oculus_id, playfab_id=playfab_id)
        send_auth_webhook(True, client_ip, custom_id, playfab_id, oculus_id)

        return jsonify({
            "PlayFabId": playfab_id,
            "SessionTicket": session_ticket,
            "EntityToken": entity_token,
            "EntityId": entity_id,
            "EntityType": entity_type,
        }), 200

    if login_request.status_code == 403:
        ban_info = login_request.json()
        if ban_info.get("errorCode") == 1002:
            ban_details = ban_info.get("errorDetails", {})
            ban_expiration_key = next(iter(ban_details.keys()), None)
            ban_expiration_list = ban_details.get(ban_expiration_key, [])
            ban_expiration = ban_expiration_list[0] if ban_expiration_list else "No expiration date provided."
            return auth_fail(client_ip, f"User banned: {ban_info.get('errorMessage', 'N/A')}", oculus_id=oculus_id, custom_id=rjson.get("CustomId"), error_code="Banned", status=403)

        error_message = ban_info.get("errorMessage", "Forbidden without ban information.")
        return auth_fail(client_ip, error_message, oculus_id=oculus_id, custom_id=rjson.get("CustomId"), error_code="PlayFabForbidden")

    error_info = login_request.json()
    error_message = error_info.get("errorMessage", "An error occurred.")
    return auth_fail(client_ip, error_message, oculus_id=oculus_id, custom_id=rjson.get("CustomId"), error_code="PlayFabError", status=login_request.status_code)


@app.route("/api/CachePlayFabId", methods=["POST"])
def cache_playfab_id():
    return jsonify({"Message": "Success"}), 200


@app.route('/api/TitleData', methods=['POST', 'GET'])
def titledata():
    response_data = {
        "AutoMuteCheckedHours": {"hours": 169},
        "AutoName_Adverbs": ["Cool", "Fine", "Bald", "Bold", "Half", "Only", "Calm", "Fab", "Ice", "Mad", "Rad", "Big", "New", "Old", "Shy"],
        "AutoName_Nouns": ["Gorilla", "Chicken", "Darling", "Sloth", "King", "Queen", "Royal", "Major", "Actor", "Agent", "Elder", "Honey", "Nurse", "Doctor", "Rebel", "Shape", "Ally", "Driver", "Deputy"],
        "CreditsData": [
            {"Title": "<color=blue>UPDATE MAKERS/PLAYFAB MANAGERS</color>", "Entries": ["L1RSON (UPDATE MAKER/PLAYFAB MANAGER)", "KITTY (OWNER/PLAYFAB MANAGER)", "Z3N (OWNER)"]},
            {"Title": "<color=yellow>CREDITS TO</color>", "Entries": ["TABLE", "L1RSON", "S4GE", "IRES", "QUIZX"]},
            {"Title": "<color=red>GAY FELLAS</color>", "Entries": ["DESK", "TABLE", "IRES", "RASP", "KEN"]}
        ],
        "BundleBoardSign": "<color=#ff4141>DISCORD.GG/Vnkh3Hr9RE</color>",
        "BundleKioskButton": "<color=#ff4141>DISCORD.GG/Vnkh3Hr9RE</color>",
        "BundleKioskSign": "<color=#ff4141>DISCORD.GG/Vnkh3Hr9RE</color>",
        "BundleLargeSign": "<color=#ff4141>DISCORD.GG/Vnkh3Hr9RE</color>",
        "EmptyFlashbackText": "FLOOR TWO NOW OPEN\n FOR BUSINESS\n\nSTILL SEARCHING FOR\nBOX LABELED 2021",
        "EnableCustomAuthentication": True,
        "GorillanalyticsChance": 4320,
        "LatestPrivacyPolicyVersion": "2024.09.20",
        "LatestTOSVersion": "2024.09.20",
        "MOTD": "<color=#bb29ff>[ WELCOME TO ORIGINAL TAG REVIVED ]</color>\n <color=#07dde8>CHRISTMUH 23!</color>\n<color=#ffff00>CREATOR/FOUNDER : Z3N</color>\n<color=#969696>CREDITS TO: IRES, L1RSON, S4GE, SCREAMINGCAT, Z3N, RASP, TABLE</color>\n<color=#ff8800>DISCORD.GG/Vnkh3Hr9RE</color>\n<color=#000000>CHANGE YOUR NAME FROM oldgorilla AS IT'S BANNABLE!</color>",
        "SeasonalStoreBoardSign": "<color=yellow>RATE THE GAME 5 STARS!</color>\n\n<color=aqua>.GG/Vnkh3Hr9RE",
        "TOS_2024.09.20": "DISCORD.GG/Vnkh3Hr9RE",
        "TOBAlreadyOwnCompTxt": "DISCORD.GG/Vnkh3Hr9RE",
        "TOBAlreadyOwnPurchaseBundle": "RETRO",
        "TOBDefCompTxt": "DISCORD.GG/Vnkh3Hr9RE",
        "TOBDefPurchaseBtnDefTxt": "RETRO",
        "UseLegacyIAP": False
    }
    return jsonify(response_data)


@app.route("/api/ConsumeOculusIAP", methods=["POST"])
def consume_oculus_iap():
    rjson = request.get_json()

    user_id = rjson.get("userID")
    nonce = rjson.get("nonce")
    sku = rjson.get("sku")

    if not all([user_id, nonce, sku]):
        return jsonify({"error": "Missing parameters"}), 400

    nonce_valid, nonce_error = validate_and_bind_nonce(nonce, user_id)
    if not nonce_valid:
        return jsonify({"error": nonce_error}), 403

    response = requests.post(
        url=f"https://graph.oculus.com/consume_entitlement?nonce={nonce}&user_id={user_id}&sku={sku}&access_token={settings.ApiKey}",
        headers={"content-type": "application/json"},
    )

    if response.json().get("success"):
        return jsonify({"result": True})
    else:
        return jsonify({"error": True})


@app.route("/api/GetAcceptedAgreements", methods=['POST', 'GET'])
def GetAcceptedAgreements():
    return jsonify({"PrivacyPolicy": "1.1.28", "TOS": "11.05.22.2"}), 200


@app.route("/api/SubmitAcceptedAgreements", methods=['POST', 'GET'])
def SubmitAcceptedAgreements():
    return jsonify({}), 200


@app.route("/api/ConsumeCodeItem", methods=["POST"])
def consume_code_item():
    rjson = request.get_json()
    code = rjson.get("itemGUID")
    playfab_id = rjson.get("playFabID")
    session_ticket = rjson.get("playFabSessionTicket")

    if not all([code, playfab_id, session_ticket]):
        return jsonify({"error": "Missing parameters"}), 400

    ticket_valid, ticket_error = validate_session_ticket(session_ticket)
    if not ticket_valid:
        return jsonify({"error": ticket_error}), 403

    raw_url = "https://github.com/redapplegtag/backendsfrr"
    response = requests.get(raw_url)

    if response.status_code != 200:
        return jsonify({"error": "GitHub fetch failed"}), 500

    lines = response.text.splitlines()
    codes = {split[0].strip(): split[1].strip() for line in lines if (split := line.split(":")) and len(split) == 2}

    if code not in codes:
        return jsonify({"result": "CodeInvalid"}), 404

    if codes[code] == "AlreadyRedeemed":
        return jsonify({"result": codes[code]}), 200

    grant_response = requests.post(
        f"https://{settings.TitleId}.playfabapi.com/Admin/GrantItemsToUsers",
        json={
            "ItemGrants": [
                {"PlayFabId": playfab_id, "ItemId": item_id, "CatalogVersion": "DLC"}
                for item_id in ["dis da cosmetics", "anotehr cposmetic", "anotehr"]
            ]
        },
        headers=settings.get_auth_headers()
    )

    if grant_response.status_code != 200:
        return jsonify({"result": "PlayFabError", "errorMessage": grant_response.json().get("errorMessage", "Grant failed")}), 500

    return jsonify({"result": "Success", "itemID": code, "playFabItemName": codes[code]}), 200


@app.route('/api/v2/GetName', methods=['POST', 'GET'])
def GetNameIg():
    return jsonify({"result": f"GORILLA{random.randint(1000,9999)}"})


@app.route("/api/photon", methods=["POST", "GET"])
def photonauth():
    rjson = request.get_json()
    if not rjson:
        return jsonify({'resultCode': 2, 'message': 'No body', 'userId': None, 'nickname': None}), 400

    ticket = rjson.get("Ticket")
    nonce = rjson.get("Nonce")
    platform = rjson.get("Platform")

    if not ticket:
        return jsonify({'resultCode': 2, 'message': 'Missing ticket', 'userId': None, 'nickname': None}), 400

    if platform != 'Quest':
        return jsonify({'resultCode': 2, 'message': 'Invalid platform', 'userId': None, 'nickname': None}), 403

    userId = ticket.split('-')[0]

    if not userId or len(userId) != 16:
        return jsonify({'resultCode': 2, 'message': 'Invalid token', 'userId': None, 'nickname': None}), 400

    stored_user = users_collection.find_one({"playfab_id": userId, "playfab_authed": True})
    if not stored_user:
        return jsonify({'resultCode': 2, 'message': 'Player has not completed PlayFab authentication', 'userId': None, 'nickname': None}), 403

    if request.method == "GET":
        if not nonce:
            return jsonify({'resultCode': 2, 'message': 'Missing nonce', 'userId': None, 'nickname': None}), 400

        oculus_id = stored_user.get("oculus_id")
        nonce_valid, nonce_error = validate_and_bind_nonce(nonce, oculus_id)
        if not nonce_valid:
            return jsonify({'resultCode': 2, 'message': nonce_error, 'userId': None, 'nickname': None}), 403

    ticket_valid, ticket_error = validate_session_ticket(ticket)
    if not ticket_valid:
        return jsonify({'resultCode': 2, 'message': ticket_error, 'userId': None, 'nickname': None}), 403

    req = requests.post(
        url=f"https://{settings.TitleId}.playfabapi.com/Server/GetUserAccountInfo",
        json={"PlayFabId": userId},
        headers=settings.get_auth_headers()
    )

    if req.status_code != 200:
        return jsonify({'resultCode': 0, 'message': 'Something went wrong', 'userId': None, 'nickname': None}), 500

    nickName = req.json().get("data", {}).get("UserInfo", {}).get("TitleInfo", {}).get("DisplayName") or None

    return jsonify({
        'resultCode': 1,
        'message': f'Authenticated user {userId.lower()} title {settings.TitleId.lower()}',
        'userId': userId.upper(),
        'nickname': nickName
    }), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9080)
