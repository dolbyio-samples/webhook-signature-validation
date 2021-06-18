# Interactivity API Webhook Signature Validation

The Dolby Interactivity API platform provides the ability for your webhook listener service to validate the integrity of an incoming event. Webhook signature validation is optional but allows you to check the signature and expiration to prevent your service from malicious actions including replay attacks. Validation ensures that the webhook payloads were actually sent by the trusted source and that the contents have not been modified.

A webhook signature is included in the request's header and can be used in your code to verify the request. The Dolby Interactivity API platform uses a private key to generate a signature; the private key changes according to a pre-defined rotation period. Your webhook listener service can use the public key to validate that the payload has been signed by the matching private key. The public key is available through public HTTP access.

For more information regarding this feature, please refer to https://dolby-io.readme.io/interactivity/docs/webhooks-validation

This project groups code samples for different languages allowing to validate webhook messages from the Dolby Interactivity API platform.
