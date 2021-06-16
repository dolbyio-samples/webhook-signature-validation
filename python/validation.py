import ed25519
import base64
import urllib.request
import json
import time

# A global variable to cache the public keys to avoid querying the api every time we want to validate a signature
pub_keys_cache = []


def get_header_components(header_signature):
    header_components = header_signature.split(",")
    timestamp, pub_key_id, signature = None, None, None
    # Header components are retrieved this way because their number and order might change in the future
    for header_component in header_components:
        if header_component.startswith("t="):
            timestamp = header_component.replace("t=", "")
        elif header_component.startswith("k="):
            pub_key_id = header_component.replace("k=", "")
        elif header_component.startswith("s="):
            signature = header_component.replace("s=", "")
    return timestamp, pub_key_id, signature


def get_public_keys_from_api():
    return json.loads(urllib.request.urlopen("https://api.voxeet.com/v1/public/keys/webhooks").read())


def get_public_key(pub_key_id):
    global pub_keys_cache
    # If public key is not in cache, then refresh public keys cache from api
    if not pub_keys_cache or pub_key_id not in pub_keys_cache:
        pub_keys_cache = get_public_keys_from_api()
        for pub_key in pub_keys_cache:
            # Translate base64 encoded keys to byte arrays now to avoid doing this every time a validation takes place
            pub_keys_cache[pub_key] = base64.b64decode(pub_keys_cache[pub_key])
    if pub_key_id in pub_keys_cache:
        # Return the VerifyingKey generated from the public key byte array
        return ed25519.VerifyingKey(pub_keys_cache[pub_key_id])
    return None


def ed25519_verify(body_content, header_signature):
    # Get timestamp and signature data from header
    timestamp, pub_key_id, signature = get_header_components(header_signature)
    if timestamp is None:
        print("Could not retrieve timestamp from header")
        return False
    if pub_key_id is None:
        print("Could not retrieve key id from header")
        return False
    if signature is None:
        print("Could not retrieve signature from header")
        return False
    # Check if webhook message is expired, here we'll use 10 minutes
    if (time.time() - int(timestamp)) > (10*60):
        print("Webhook message expired")
        return False
    # Concatenate timestamp and message body to re-create payload
    payload = timestamp + "." + body_content
    # Get byte values from payload
    payload_bytes = str.encode(payload)
    # Get decoded byte values from signature
    signature_bytes = base64.b64decode(signature)
    # Get public verification key from cache or api
    pub_key = get_public_key(pub_key_id)
    if pub_key is None:
        print("Error retrieving public key: " + pub_key_id)
        return False
    # Use the public key and the payload bytes to verify the signature
    try:
        pub_key.verify(signature_bytes, payload_bytes)
        print("Signature is VALID")
        return True
    except ed25519.BadSignatureError:
        print("Signature is INVALID")
    return False
