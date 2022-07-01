# Web Worker Webhook Signature Validation

The purpose of this project is to showcase and test the Web Worker implementation for validating the Dolby-Signature webhook Ed25519 signature header. Currently only tested in the Cloudflare Workers environment with Node JS polyfill to enable the use Buffer.

Web workers may not have the standard Node.js Crypto package available, so this is used as an alternative by using the Web API version of crypto (https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).

## Prerequisites

- Web Worker Environment
- NPM
- TypeScript
- Node JS support in Web worker
