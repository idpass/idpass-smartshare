/*
 * Copyright (C) 2021 Newlogic Pte. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.idpass.smartshare.connection;

import com.goterl.lazysodium.LazySodium;
import com.goterl.lazysodium.LazySodiumAndroid;
import com.goterl.lazysodium.SodiumAndroid;
import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.Box;
import com.goterl.lazysodium.interfaces.DiffieHellman;
import com.goterl.lazysodium.interfaces.SecretBox;
import com.goterl.lazysodium.interfaces.Sign;
import com.goterl.lazysodium.utils.Key;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingDeque;

/**
 * The wrapper class that uses Libsodium's cryptographic primitives.
 */
public class EncryptionUtils {
    private static final String TAG = EncryptionUtils.class.getName();
    private SodiumAndroid sodium;
    private LazySodiumAndroid lazySodium;
    private byte[] publicKeyCurve25519;
    private byte[] secretKeyCurve25519;
    private byte[] publicKeyED25519;
    private byte[] secretKeyED25519;

    public EncryptionUtils() {
        sodium = new SodiumAndroid();
        lazySodium = new LazySodiumAndroid(sodium);
        regenerateKeyPair();
    }

    /**
     * Initializes new ED25519 key pairs.
     */
    public void regenerateKeyPair() {
        publicKeyED25519 = new byte[Sign.ED25519_PUBLICKEYBYTES];
        secretKeyED25519 = new byte[Sign.ED25519_SECRETKEYBYTES];

        publicKeyCurve25519 = new byte[Sign.CURVE25519_PUBLICKEYBYTES];
        secretKeyCurve25519 = new byte[Sign.CURVE25519_SECRETKEYBYTES];

        int status = sodium.crypto_sign_keypair(publicKeyED25519, secretKeyED25519);
        status = sodium.crypto_sign_ed25519_pk_to_curve25519(publicKeyCurve25519, publicKeyED25519);
        status = sodium.crypto_sign_ed25519_sk_to_curve25519(secretKeyCurve25519, secretKeyED25519);
    }

    /**
     * Returns the ED25519 public key as a string
     *
     * @return The ED25519 public key in hex string format
     */
    public String getPublicKeyED25519AsString() {
        return LazySodium.toHex(publicKeyED25519);
    }

    /**
     * This is used in the key exchange handshake. It verifies a correctly computed
     * keyed hash of a public key payload field using the derived secret key between
     * the two devices.
     *
     * @param kex The message type for this handshake message
     * @return Returns true if the keyed hash matches
     * @throws JSONException
     * @throws SodiumException
     */
    public boolean verifyKexJson(String kex) throws JSONException, SodiumException {
        JSONObject json = new JSONObject(kex);
        String pk = json.getString("pk");
        String hash = json.getString("hash");

        byte[] ed25519 = LazySodium.toBin(pk);
        byte[] curve25519 = new byte[Sign.CURVE25519_PUBLICKEYBYTES];
        if (0 != sodium.crypto_sign_ed25519_pk_to_curve25519(curve25519, ed25519)) {
            throw new SodiumException("error: ED25519 to Curve25519 Conversion");
        }

        DiffieHellman.Lazy dh = (DiffieHellman.Lazy) lazySodium;
        Key publicKey = Key.fromBytes(curve25519);
        Key secretKey = Key.fromBytes(secretKeyCurve25519);
        Key sharedKey = dh.cryptoScalarMult(secretKey, publicKey);

        String computedHash = lazySodium.cryptoGenericHash(pk, sharedKey);
        return computedHash.equals(hash);
    }

    /**
     * Creates a kex handshake message to send a public key to peer. It's verifiability
     * is through a keyed hash using the derived secret key of the two devices.
     *
     * @param myPubKey   The public key to send to remote peer
     * @param peerPubKey The remote peer's public key
     * @return Returns a key handshake message
     * @throws JSONException
     * @throws SodiumException
     */
    public String createKexJson(String myPubKey, String peerPubKey) throws JSONException, SodiumException {
        byte[] ed25519 = LazySodium.toBin(peerPubKey);
        byte[] curve25519 = new byte[Sign.CURVE25519_PUBLICKEYBYTES];
        if (0 != sodium.crypto_sign_ed25519_pk_to_curve25519(curve25519, ed25519)) {
            throw new SodiumException("error: ED25519 to Curve25519 Conversion");
        }

        DiffieHellman.Lazy dh = (DiffieHellman.Lazy) lazySodium;
        Key publicKey = Key.fromBytes(curve25519);
        Key secretKey = Key.fromBytes(secretKeyCurve25519);
        Key sharedKey = dh.cryptoScalarMult(secretKey, publicKey);

        String myPubKeyHash = lazySodium.cryptoGenericHash(myPubKey, sharedKey);

        JSONObject json = new JSONObject();
        json.put("type", "kex");
        json.put("pk", myPubKey);
        json.put("hash", myPubKeyHash);

        return json.toString();
    }

    /**
     * Encrypts the payload through a shared key between the two devices.
     *
     * @param payload       The payload plaintext to encrypt
     * @param pubkeyED25519 The remote peer's ED25519 public key
     * @return Returns a structured message with an encrypted payload field
     * @throws JSONException
     * @throws SodiumException
     */
    public String encrypt(String payload, String pubkeyED25519) throws JSONException, SodiumException {
        DiffieHellman.Lazy dh = (DiffieHellman.Lazy) lazySodium;
        SecretBox.Lazy box = (SecretBox.Lazy) lazySodium;
        Key publicKey = Key.fromHexString(edPub2curvePub(pubkeyED25519));
        Key secretKey = Key.fromBytes(secretKeyCurve25519);
        Key sharedKey = dh.cryptoScalarMult(secretKey, publicKey);

        byte[] nonce = lazySodium.nonce(Box.NONCEBYTES);
        JSONObject json = new JSONObject();
        String ePayload = box.cryptoSecretBoxEasy(payload, nonce, sharedKey);
        json.put("type", "msg");
        json.put("ePayload", ePayload);
        json.put("nonce", LazySodium.toHex(nonce));
        json.put("pk", LazySodium.toHex(publicKeyED25519));

        return json.toString();
    }

    /**
     * Decrypts the encrypted payload field of the structured message.
     *
     * @param jsonPayload The received structured message
     * @return Returns the payload string in plaintext
     * @throws JSONException
     * @throws SodiumException
     */
    public String decrypt(String jsonPayload) throws JSONException, SodiumException {
        DiffieHellman.Lazy dh = (DiffieHellman.Lazy) lazySodium;
        SecretBox.Lazy box = (SecretBox.Lazy) lazySodium;

        JSONObject json = new JSONObject(jsonPayload);
        String pubkey = json.get("pk").toString();

        byte[] ed25519 = LazySodium.toBin(pubkey);
        byte[] curve25519 = new byte[Sign.CURVE25519_PUBLICKEYBYTES];
        if (0 != sodium.crypto_sign_ed25519_pk_to_curve25519(curve25519, ed25519)) {
            throw new SodiumException("error: ED25519 to Curve25519 conversion");
        }

        byte[] nonce = LazySodium.toBin(json.get("nonce").toString());
        String ePayload = json.get("ePayload").toString();
        Key publicKey = Key.fromBytes(curve25519);

        Key secretKey = Key.fromBytes(secretKeyCurve25519);
        Key sharedKey = dh.cryptoScalarMult(secretKey, publicKey);
        String payload = box.cryptoSecretBoxOpenEasy(ePayload, nonce, sharedKey);

        return payload;
    }

    /**
     * This is a debug key pair to bypass QR code and debug Bluetooth
     */
    public void regenerateKeyPairDebug() {
        String pkDebug = "14EEF98AFF6AAB9D8DB7874D79C9E96BE51D2158F7FB11D5FF7E08BCC01FDA4F";
        String skDebug = "303132333435363738394142434445463031323334353637383941424344454614EEF98AFF6AAB9D8DB7874D79C9E96BE51D2158F7FB11D5FF7E08BCC01FDA4F";

        publicKeyED25519 = new byte[Sign.ED25519_PUBLICKEYBYTES];
        secretKeyED25519 = new byte[Sign.ED25519_SECRETKEYBYTES];

        publicKeyCurve25519 = new byte[Sign.CURVE25519_PUBLICKEYBYTES];
        secretKeyCurve25519 = new byte[Sign.CURVE25519_SECRETKEYBYTES];

        // sodium.crypto_sign_keypair(publicKeyED25519, secretKeyED25519);
        publicKeyED25519 = LazySodium.toBin(pkDebug);
        secretKeyED25519 = LazySodium.toBin(skDebug);

        sodium.crypto_sign_ed25519_pk_to_curve25519(publicKeyCurve25519, publicKeyED25519);
        sodium.crypto_sign_ed25519_sk_to_curve25519(secretKeyCurve25519, secretKeyED25519);
    }

    /**
     * Converts an ED25519 public key to Curve25519 public key. The Curve25519 key
     * will be used for encryption.
     *
     * @param edPub An ED25519 public key in hex string representation
     * @return Returns the equivalent Curve25519 public key
     * @throws SodiumException
     */
    private String edPub2curvePub(String edPub) throws SodiumException {
        byte[] ed25519 = LazySodium.toBin(edPub);
        byte[] curve25519 = new byte[Sign.CURVE25519_PUBLICKEYBYTES];
        if (0 != sodium.crypto_sign_ed25519_pk_to_curve25519(curve25519, ed25519)) {
            throw new SodiumException("error: ED25519 to Curve25519 conversion");
        }
        return LazySodium.toHex(curve25519);
    }

    /**
     * Encrypts payload and chunk it into small pieces. The first chunk type is the
     * begin chunk that describes the total count of chunks, the size and hash of the
     * payload. It is followed by a series of chunk types with the chunk content
     * and its fractional percentage relative to the whole. The last is the end chunk
     * which contains the nonce used to encrypt the payload.
     *
     * @param payload The plaintext payload
     * @param pubkeyED25519 The peer public key
     * @return Returns chunks of the encrypted payload
     */
    public BlockingQueue<JSONObject> chunkPayload(String payload, String pubkeyED25519) {
        try {
            DiffieHellman.Lazy dh = (DiffieHellman.Lazy) lazySodium;
            SecretBox.Lazy box = (SecretBox.Lazy) lazySodium;
            Key publicKey = Key.fromHexString(edPub2curvePub(pubkeyED25519));
            Key secretKey = Key.fromBytes(secretKeyCurve25519);
            Key sharedKey = dh.cryptoScalarMult(secretKey, publicKey);

            byte[] nonce = lazySodium.nonce(Box.NONCEBYTES);
            String ePayload = box.cryptoSecretBoxEasy(payload, nonce, sharedKey);

            BlockingQueue<JSONObject> outbound = new LinkedBlockingDeque<>();
            List<String> chunks = Utils.splitPayload(ePayload);
            float chunksCount = chunks.size();

            JSONObject beginJson = new JSONObject();
            beginJson.put("type", "begin");
            beginJson.put("count", chunksCount);
            beginJson.put("size", payload.getBytes().length);
            beginJson.put("hash", Utils.computeHash(payload));

            outbound.add(beginJson);
            int n = 1;
            for (String chunk : chunks) {
                JSONObject chunkJson = new JSONObject();
                chunkJson.put("type", "chunk");
                chunkJson.put("percent", n / chunksCount);
                chunkJson.put("data", chunk);
                outbound.add(chunkJson);
                n++;
            }
            JSONObject endJson = new JSONObject();
            endJson.put("type", "end");
            endJson.put("nonce", LazySodium.toHex(nonce));
            outbound.add(endJson);

            return outbound;
        } catch (JSONException | SodiumException e) {
            return null;
        }
    }

    /**
     * Decrypts the received and encrypted payload.
     *
     * @param ePayload The accumulated received and encrypted payload.
     * @param pubkey The peer public key.
     * @param nonceStr The nonce used to encrypt the payload
     * @return Returns the decrypted payload.
     * @throws JSONException
     * @throws SodiumException
     */
    public String decryptInbound(String ePayload, String pubkey, String nonceStr) throws JSONException, SodiumException {
        DiffieHellman.Lazy dh = (DiffieHellman.Lazy) lazySodium;
        SecretBox.Lazy box = (SecretBox.Lazy) lazySodium;

        byte[] ed25519 = LazySodium.toBin(pubkey);
        byte[] curve25519 = new byte[Sign.CURVE25519_PUBLICKEYBYTES];
        if (0 != sodium.crypto_sign_ed25519_pk_to_curve25519(curve25519, ed25519)) {
            throw new SodiumException("error: ED25519 to Curve25519 conversion");
        }

        byte[] nonce = LazySodium.toBin(nonceStr);
        Key publicKey = Key.fromBytes(curve25519);

        Key secretKey = Key.fromBytes(secretKeyCurve25519);
        Key sharedKey = dh.cryptoScalarMult(secretKey, publicKey);
        String payload = box.cryptoSecretBoxOpenEasy(ePayload, nonce, sharedKey);

        return payload;
    }
}
