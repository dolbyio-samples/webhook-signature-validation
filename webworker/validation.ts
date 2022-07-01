const encoder = new TextEncoder();
const savedKeys: { [key: string]: string } = {};

export const testSPKISignature = async (
  signature: string,
  publicKeyValue: string,
  payloadBytes: Uint8Array
): Promise<boolean> => {
  try {
    // In order to avoid remove any depedancy on Node.js
    // in your web worker, import the needed functions to
    // replace Buffer.from and Buffer.concat
    const signatureBytes = Buffer.from(signature, "base64");

    const publicKey = Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"), // Static value
      Buffer.from(publicKeyValue, "base64"),
    ]);

    const cKey = await crypto.subtle.importKey(
      "spki",
      publicKey, // Create an array from the der data string
      {
        name: "NODE-ED25519", // Not all webworkers may support this method, Cloudflare Workers currently do support this method
        namedCurve: "NODE-ED25519",
      },
      false,
      ["verify"] // spki (public key) can only be used to verify signatures
    );

    const results = await crypto.subtle.verify(
      "NODE-ED25519",
      cKey,
      signatureBytes,
      payloadBytes
    );

    return results;
  } catch (err) {
    console.log(err);
  }

  return false;
};

export const validateDolbyRequest = async (
  request: Request
): Promise<boolean> => {
  const signatureHeader = request.headers.get("Dolby-Signature");
  const data = await request.clone().text();

  if (!signatureHeader) {
    throw Error("signatureHeader is a required header");
  }

  const strings = signatureHeader.split(",");

  let timestamp, key, signature;

  strings.forEach((s) => {
    const [stringKey, value] = s.split("=");

    if (stringKey === "t") {
      timestamp = value;
    } else if (stringKey === "k") {
      key = value;
    } else if (stringKey === "s") {
      signature = value;
    }
  });

  if (!timestamp || !key || !signature) {
    throw Error("Dolby Signature is missing required information");
  }

  // Now in seconds
  const now = Date.now() / 1000;

  // Header timestamp as a number
  const timestampAsInt = parseInt(timestamp, 10);

  const expireTimeInMinutes = 10;
  const expirationTimeInSeconds = expireTimeInMinutes * 60;

  // As based on Dolby's documentation, we treat any timestamp
  // older then 10 minutes old as expired
  if (timestampAsInt < now - expirationTimeInSeconds) {
    throw Error("Dolby Signature timestamp has expired");
  }

  // If we haven't already fetched our key from the public API
  // then we need to fetch the most recent round of public keys
  if (!savedKeys[key]) {
    const response = await fetch(
      "https://api.voxeet.com/v1/public/keys/webhooks"
    );

    if (response.status !== 200) {
      throw Error(
        "Validate Signature received an error fetching the public keys"
      );
    }

    const body: any = await response.json();

    if (body && body[key]) {
      savedKeys[key] = body[key];
    } else {
      throw Error("Validate Signature is unable to find public key");
    }
  }

  const publicKeyValue = savedKeys[key];

  const payload = `${timestamp}.${data}`;
  const payloadBytes = encoder.encode(payload);

  const results = await testSPKISignature(
    signature,
    publicKeyValue,
    payloadBytes
  );

  if (!results) {
    throw Error("Dolby Signature was invalid");
  }

  return results;
};
