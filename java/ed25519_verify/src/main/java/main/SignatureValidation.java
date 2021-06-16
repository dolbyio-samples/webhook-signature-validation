package main;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import com.google.gson.JsonObject;

public class SignatureValidation {

    // A global variable to cache the public keys to avoid querying the api every time we want to validate a signature
    Map<String, byte[]> publicKeysCache = null;

    private JsonObject getPublicKeysFromApi() {
        return new JsonObject(IOUtils.toString(new URL("https://staging-api.voxeet.com/v1/public/keys/webhooks"), StandardCharsets.UTF_8));
    }

    private byte[] getPublicKey(String pubKeyId){
        // If public key is not in cache, then refresh public keys cache from api
        if (publicKeysCache == null || !publicKeysCache.containsKey(pubKeyId)) {
            publicKeysCache = new HashMap<>();
            JsonObject publicKeysJson = getPublicKeysFromApi();
            for (Map.Entry<String, JsonElement> entry: publicKeysJson.entrySet()) {
                // Translate base64 encoded keys to byte arrays now to avoid doing this every time a validation takes place
                publicKeysCache.put(entry.getKey(), Base64.getDecoder().decode(entry.getValue().getAsString()));
            }
        }
        if (publicKeysCache.containsKey(pubKeyId))
            return publicKeysCache.get(pubKeyId);
        return null;
    }

    public boolean ed25519Verify(String messageBody, String messageHeader) {
        // Get timestamp, public key id and signature data from header
        String timestamp = null;
        String publicKeyId = null;
        String signature = null;
        String[] messageHeaderComponents = messageHeader.split(",");
        if (messageHeaderComponents.length != 3) {
            System.out.println("Invalid header format");
            return false;
        }
        // Header components are retrieved this way because their number and order might change in the future
        for (String comp : messageHeaderComponents) {
            if (comp.startsWith("t="))
                timestamp = comp.replace("t=", "");
            else if (comp.startsWith("k="))
                publicKeyId = comp.replace("k=", "");
            else if (comp.startsWith("s="))
                signature = comp.replace("s=", "");
        }
        // Check to make sure all data has been correctly retrieved
        if (timestamp == null)
            System.out.println("Could not retrieve timestamp from header");
        if (publicKeyId == null)
            System.out.println("Could not retrieve key id from header");
        if (signature == null)
            System.out.println("Could not retrieve signature from header");
        if (timestamp == null || publicKeyId == null || signature == null)
            return false;
        // Optional step : check message expiration, here we choose an arbitrary expiration time of 10 minutes
        if ((Instant.now().getEpochSecond() - Integer.parseInt(timestamp)) > (10*60)) {
            System.out.println("Webhook message expired");
            return false;
        }
        // Concatenate timestamp and message body to re-create payload
        String payload = String.format("%s.%s", timestamp, messageBody);
        // Get byte values from payload
        byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
        // Get decoded byte values from signature
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        // Get public verification key from cache or api
        byte[] publicKeyBytes = getPublicKey(publicKeyId);
        if (publicKeyBytes == null || publicKeyBytes.length == 0) {
            System.out.println("Error retrieving public key: " + publicKeyId);
            return false;
        }
        // Use the public key and the payload bytes to verify the signature
        Ed25519PublicKeyParameters publicKeyParameters = new Ed25519PublicKeyParameters(publicKeyBytes, 0);
        Signer verifier = new Ed25519Signer();
        verifier.init(false, publicKeyParameters);
        verifier.update(payloadBytes, 0, payloadBytes.length);
        if (verifier.verifySignature(signatureBytes)) {
            System.out.println("Signature is VALID");
            return true;
        }
        System.out.println("Signature is INVALID");
        return false;
    }
}
