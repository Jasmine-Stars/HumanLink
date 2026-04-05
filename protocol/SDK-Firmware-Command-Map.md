# SDK ↔ Firmware Command Map (Current Implementation)

This document is based on actual code paths in:
- `sdk/hardware/usb_bridge.py`
- `sdk/hardware/protocol.py`
- `sdk/client.py`
- `firmware/src/main.cpp`
- `firmware/include/protocol.h`

## 1. USB Bridge Transport

Wire format:
- UTF-8 JSON
- one line per message
- newline (`\n`) delimited

SDK encode/decode:
- encode: `sdk/hardware/protocol.py:20`
- decode: `sdk/hardware/protocol.py:24`

Serial bridge:
- auto-detect port: `sdk/hardware/usb_bridge.py:19`
- send JSON: `sdk/hardware/usb_bridge.py:49`
- read JSON with timeout: `sdk/hardware/usb_bridge.py:54`

## 2. SDK Commands Sent to Firmware

### `status`
Sender:
- `sdk/client.py:31`

Request:
```json
{"cmd":"status"}
```

Expected response:
```json
{
  "status":"ok",
  "state":"idle|authenticating",
  "provisioned":true,
  "enrolled":3,
  "protocol":"0.3",
  "device_did":"did:key:..."
}
```

Firmware handler:
- `firmware/src/main.cpp:201` (`handleStatus`)

### `getDID`
Sender:
- `sdk/client.py:37`

Request:
```json
{"cmd":"getDID"}
```

Expected response:
```json
{
  "status":"ok",
  "device_did":"did:key:...",
  "protocol":"0.3",
  "pubkey":"<base64>"
}
```

Firmware handler:
- `firmware/src/main.cpp:208` (`handleGetDid`)

### `auth`
Sender:
- `sdk/client.py:49`

SDK build steps:
1. Build assertion skeleton
2. Compute `h_doc = sha256(canonical(skeleton))`
3. Send request below

Request:
```json
{
  "cmd":"auth",
  "h_doc":"<hex64>",
  "nonce":"<hex16>",
  "display":{
    "title":"Command Approval",
    "risk":"high|medium|low"
  }
}
```

Expected success response:
```json
{
  "status":"ok",
  "protocol":"0.3",
  "matched_id":1,
  "score":188,
  "sensor_serial":"<hex64>",
  "nonce":"<hex16>",
  "signed_hash":"<hex64>",
  "sig":"<base64>",
  "pubkey":"<base64>"
}
```

Firmware handler:
- `firmware/src/main.cpp:219` (`handleAuth`)

### `cancel`
SDK currently does not call this command, but firmware supports it.

Request:
```json
{"cmd":"cancel"}
```

Firmware handler:
- `firmware/src/main.cpp:214` (`handleCancel`)

## 3. Error Response Format

Firmware error response:
```json
{"status":"err","code":<int>,"msg":"..."}
```

SDK mapping:
- `sdk/hardware/protocol.py:10`
- `sdk/hardware/protocol.py:32`

Code mapping:
- `1 TIMEOUT`
- `2 NO_MATCH`
- `3 SENSOR_ERROR`
- `4 SE_ERROR`
- `5 BAD_INPUT`
- `6 NOT_ENROLLED`
- `7 SIGN_FAIL`

## 4. signedHash Formula (as implemented)

Firmware computes:

`signedHash = SHA-256(matched_id[2B] || score[2B] || sensor_serial[32B] || nonce[8B] || h_doc[32B])`

Source:
- `firmware/src/main.cpp:134` (`computeSignedHash`)
- constants in `firmware/include/protocol.h`

SDK rebuilds the same formula in verification:
- `sdk/crypto/hash_engine.py:41`

## 5. Firmware Files Traversed

- `firmware/.gitignore`
- `firmware/platformio.ini`
- `firmware/.vscode/extensions.json`
- `firmware/include/atecc608a.h`
- `firmware/include/jm101.h`
- `firmware/include/protocol.h`
- `firmware/include/README`
- `firmware/lib/README`
- `firmware/src/atecc608a.cpp`
- `firmware/src/jm101.cpp`
- `firmware/src/main.cpp`
- `firmware/test/README`

