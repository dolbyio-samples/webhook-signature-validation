const { createPublicKey, verify } = require('crypto');
const axios = require('axios');

/**
 * Extract the components from the HTTP header.
 * @param headerSignature HTTP Header.
 * @returns The timestamp, public key ID and the signature.
 */
const getHeaderComponents = (headerSignature: string) => {
    const components: string[] = headerSignature.split(',');
    let timestamp: string | undefined;
    let pubKeyId: string | undefined;
    let signature: string | undefined;

    for (let index = 0; index < components.length; index++) {
        const component: string = components[index];
        if (component.indexOf('t=') >= 0) {
            timestamp = component.replace('t=', '');
        } else if (component.indexOf('k=') >= 0) {
            pubKeyId = component.replace('k=', '');
        } else if (component.indexOf('s=') >= 0) {
            signature = component.replace('s=', '');
        }
    }

    return {
        timestamp,
        pubKeyId,
        signature
    };
};

/**
 * Gets the public key from the Dolby.io server.
 * @param keyId Identifier of the public key.
 * @returns the public key.
 */
const getPublicKey = async (keyId: string): Promise<string | undefined> => {
    const url = 'https://comms.api.dolby.io/v1/public/keys/webhooks';
    const response = await axios.get(url);
    return response.data[keyId];
}

const ed25519Verify = async (bodyContent: string, headerSignature: string) => {
    // Get timestamp and signature data from header
    const { timestamp, pubKeyId, signature } = getHeaderComponents(headerSignature);
    if (!timestamp) {
        console.error('Could not retrieve timestamp from header');
        return false;
    }
    if (!pubKeyId) {
        console.error('Could not retrieve key id from header');
        return false;
    }
    if (!signature) {
        console.error('Could not retrieve signature from header');
        return false;
    }

    // Check if webhook message is expired, here we'll use 10 minutes
    if ((new Date().getSeconds() - parseInt(timestamp)) > (10 * 60)) {
        console.error('Webhook message expired');
        return false;
    }

    // Concatenate timestamp and message body to re-create payload
    const payload = `${timestamp}.${bodyContent}`
    const baPayload = Buffer.from(payload, 'utf8');

    // Get decoded byte values from signature
    const baSignature = Buffer.from(signature, 'base64');

    // Get public verification key from api
    const publicKey = await getPublicKey(pubKeyId);
    if (!publicKey) {
        console.error(`Error retrieving public key: ${pubKeyId}`);
        return false;
    }

    const key = Buffer.concat([
        Buffer.from('302a300506032b6570032100', 'hex'), // Static value
        Buffer.from(publicKey, 'base64')
    ]);

    const verifyKey = createPublicKey({
        format: 'der',
        type: 'spki',
        key,
    });

    return verify(null, baPayload, verifyKey, baSignature);
};
