#include <Arduino.h>

#include <mbedtls/base64.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

namespace {

constexpr char kProtocolVersion[] = "0.3";
constexpr uint32_t kSerialBaud = 115200;
constexpr uint16_t kMatchedId = 1;
constexpr uint16_t kMatchScore = 188;
constexpr uint8_t kEnrolledCount = 3;
constexpr uint8_t kSensorSerial[32] = {
    0xA3, 0xB4, 0xC5, 0xD6, 0xE7, 0xF8, 0x10, 0x21,
    0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xA9,
    0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F, 0x11, 0x22,
    0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
};
constexpr uint8_t kPrivateKey[32] = {
    0x0A, 0x9E, 0x8A, 0x14, 0xD7, 0xC0, 0x96, 0xB4,
    0x53, 0x41, 0x17, 0x01, 0x62, 0x50, 0xF7, 0x76,
    0x05, 0x0C, 0x3D, 0x0B, 0xA1, 0xB1, 0x30, 0x6C,
    0x1C, 0x6B, 0xE1, 0xB8, 0x8E, 0x47, 0xEB, 0x02,
};
constexpr uint8_t kPublicKey[64] = {
    0x14, 0x57, 0x24, 0x7F, 0xFA, 0xC5, 0xBA, 0x50,
    0x92, 0x74, 0x32, 0x3A, 0x67, 0x81, 0x6C, 0xA6,
    0x1D, 0xBB, 0xEC, 0x30, 0x7E, 0x92, 0x62, 0x77,
    0x34, 0xD7, 0xB6, 0x01, 0x55, 0xEA, 0x4F, 0x8E,
    0x44, 0xC5, 0x6D, 0x30, 0x06, 0x19, 0x16, 0x61,
    0x63, 0x11, 0x32, 0x67, 0x9A, 0x37, 0xA6, 0x73,
    0xCD, 0x70, 0xA9, 0xC5, 0x69, 0x22, 0x9C, 0x3A,
    0x44, 0xE1, 0xCC, 0x19, 0x84, 0xA7, 0x57, 0xBF,
};
constexpr char kDeviceDid[] =
    "did:key:z81eMDXfXd8oa9zX6gd2tusvHav22R4gPtrEVWkh9ay9RKPaHx2kUdRXxzvB8UguZTeYPPw3Pxd3MeZZAXhB84oQNHL";

String serialBuffer;
String deviceState = "idle";
bool cancelRequested = false;

String bytesToHex(const uint8_t *data, size_t len) {
  static const char hex[] = "0123456789abcdef";
  String out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out += hex[(data[i] >> 4) & 0x0F];
    out += hex[data[i] & 0x0F];
  }
  return out;
}

bool hexToBytes(const String &hex, uint8_t *out, size_t expectedLen) {
  if (hex.length() != expectedLen * 2) {
    return false;
  }
  auto decodeNibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
  };
  for (size_t i = 0; i < expectedLen; ++i) {
    int hi = decodeNibble(hex[i * 2]);
    int lo = decodeNibble(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) {
      return false;
    }
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return true;
}

String b64Encode(const uint8_t *data, size_t len) {
  unsigned char out[128];
  size_t olen = 0;
  int rc = mbedtls_base64_encode(out, sizeof(out), &olen, data, len);
  if (rc != 0) {
    return "";
  }
  if (olen < sizeof(out)) {
    out[olen] = '\0';
  }
  return String(reinterpret_cast<const char *>(out)).substring(0, olen);
}

bool extractJsonString(const String &json, const char *key, String *out) {
  String token = "\"" + String(key) + "\"";
  int keyPos = json.indexOf(token);
  if (keyPos < 0) {
    return false;
  }
  int colonPos = json.indexOf(':', keyPos + token.length());
  if (colonPos < 0) {
    return false;
  }
  int firstQuote = json.indexOf('"', colonPos + 1);
  if (firstQuote < 0) {
    return false;
  }
  int secondQuote = firstQuote + 1;
  while (secondQuote < static_cast<int>(json.length())) {
    if (json[secondQuote] == '"' && json[secondQuote - 1] != '\\') {
      break;
    }
    ++secondQuote;
  }
  if (secondQuote >= static_cast<int>(json.length())) {
    return false;
  }
  *out = json.substring(firstQuote + 1, secondQuote);
  return true;
}

bool computeSignedHash(const uint8_t *hDoc, const uint8_t *nonce, uint8_t *outHash) {
  uint8_t payload[76];
  payload[0] = static_cast<uint8_t>((kMatchedId >> 8) & 0xFF);
  payload[1] = static_cast<uint8_t>(kMatchedId & 0xFF);
  payload[2] = static_cast<uint8_t>((kMatchScore >> 8) & 0xFF);
  payload[3] = static_cast<uint8_t>(kMatchScore & 0xFF);
  memcpy(payload + 4, kSensorSerial, 32);
  memcpy(payload + 36, nonce, 8);
  memcpy(payload + 44, hDoc, 32);
  return mbedtls_sha256_ret(payload, sizeof(payload), outHash, 0) == 0;
}

bool signDigest(const uint8_t *digest, uint8_t *signatureOut) {
  mbedtls_ecdsa_context ctx;
  mbedtls_mpi r;
  mbedtls_mpi s;
  mbedtls_ecdsa_init(&ctx);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);

  bool ok = false;
  if (mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
    goto cleanup;
  }
  if (mbedtls_mpi_read_binary(&ctx.d, kPrivateKey, sizeof(kPrivateKey)) != 0) {
    goto cleanup;
  }
  if (mbedtls_mpi_read_binary(&ctx.Q.X, kPublicKey, 32) != 0) {
    goto cleanup;
  }
  if (mbedtls_mpi_read_binary(&ctx.Q.Y, kPublicKey + 32, 32) != 0) {
    goto cleanup;
  }
  if (mbedtls_mpi_lset(&ctx.Q.Z, 1) != 0) {
    goto cleanup;
  }
  if (mbedtls_ecdsa_sign_det(&ctx.grp, &r, &s, &ctx.d, digest, 32, MBEDTLS_MD_SHA256) != 0) {
    goto cleanup;
  }
  if (mbedtls_mpi_write_binary(&r, signatureOut, 32) != 0) {
    goto cleanup;
  }
  if (mbedtls_mpi_write_binary(&s, signatureOut + 32, 32) != 0) {
    goto cleanup;
  }
  ok = true;

cleanup:
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&r);
  mbedtls_ecdsa_free(&ctx);
  return ok;
}

void emitReady() {
  Serial.printf(
      "{\"event\":\"ready\",\"protocol\":\"%s\",\"device_did\":\"%s\"}\n",
      kProtocolVersion, kDeviceDid);
}

void emitError(int code, const char *msg) {
  Serial.printf("{\"status\":\"err\",\"code\":%d,\"msg\":\"%s\"}\n", code, msg);
}

void handleStatus() {
  Serial.printf(
      "{\"status\":\"ok\",\"state\":\"%s\",\"provisioned\":true,\"enrolled\":%u,"
      "\"protocol\":\"%s\",\"device_did\":\"%s\"}\n",
      deviceState.c_str(), kEnrolledCount, kProtocolVersion, kDeviceDid);
}

void handleGetDid() {
  String pubkeyB64 = b64Encode(kPublicKey, sizeof(kPublicKey));
  Serial.printf(
      "{\"status\":\"ok\",\"device_did\":\"%s\",\"protocol\":\"%s\",\"pubkey\":\"%s\"}\n",
      kDeviceDid, kProtocolVersion, pubkeyB64.c_str());
}

void handleCancel() {
  cancelRequested = true;
  deviceState = "idle";
  Serial.println("{\"status\":\"ok\",\"msg\":\"cancelled\"}");
}

void handleAuth(const String &json) {
  String hDocHex;
  String nonceHex;
  if (!extractJsonString(json, "h_doc", &hDocHex) || !extractJsonString(json, "nonce", &nonceHex)) {
    emitError(5, "missing h_doc or nonce");
    return;
  }

  uint8_t hDoc[32];
  uint8_t nonce[8];
  if (!hexToBytes(hDocHex, hDoc, sizeof(hDoc)) || !hexToBytes(nonceHex, nonce, sizeof(nonce))) {
    emitError(5, "bad hex input");
    return;
  }

  cancelRequested = false;
  deviceState = "authenticating";
  delay(150);
  if (cancelRequested) {
    handleCancel();
    return;
  }

  uint8_t signedHash[32];
  uint8_t signature[64];
  if (!computeSignedHash(hDoc, nonce, signedHash)) {
    deviceState = "idle";
    emitError(4, "sha256 failed");
    return;
  }
  if (!signDigest(signedHash, signature)) {
    deviceState = "idle";
    emitError(7, "sign failed");
    return;
  }

  String sigB64 = b64Encode(signature, sizeof(signature));
  String pubkeyB64 = b64Encode(kPublicKey, sizeof(kPublicKey));
  deviceState = "idle";
  Serial.printf(
      "{\"status\":\"ok\",\"protocol\":\"%s\",\"matched_id\":%u,\"score\":%u,"
      "\"sensor_serial\":\"%s\",\"nonce\":\"%s\",\"signed_hash\":\"%s\","
      "\"sig\":\"%s\",\"pubkey\":\"%s\"}\n",
      kProtocolVersion,
      kMatchedId,
      kMatchScore,
      bytesToHex(kSensorSerial, sizeof(kSensorSerial)).c_str(),
      nonceHex.c_str(),
      bytesToHex(signedHash, sizeof(signedHash)).c_str(),
      sigB64.c_str(),
      pubkeyB64.c_str());
}

void handleLine(const String &line) {
  String cmd;
  if (!extractJsonString(line, "cmd", &cmd)) {
    emitError(5, "missing cmd");
    return;
  }

  if (cmd == "status") {
    handleStatus();
    return;
  }
  if (cmd == "getDID") {
    handleGetDid();
    return;
  }
  if (cmd == "cancel") {
    handleCancel();
    return;
  }
  if (cmd == "auth") {
    handleAuth(line);
    return;
  }
  emitError(5, "unknown command");
}

}  // namespace

void setup() {
  Serial.begin(kSerialBaud);
  delay(200);
  emitReady();
}

void loop() {
  while (Serial.available() > 0) {
    char ch = static_cast<char>(Serial.read());
    if (ch == '\n') {
      String line = serialBuffer;
      serialBuffer = "";
      line.trim();
      if (line.length() > 0) {
        handleLine(line);
      }
    } else if (ch != '\r') {
      serialBuffer += ch;
    }
  }
}
