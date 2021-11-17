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

package org.idpass.smartshare.bluetooth;

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

    public void regenerateKeyPair() {
        publicKeyED25519 = new byte[Sign.ED25519_PUBLICKEYBYTES];
        secretKeyED25519 = new byte[Sign.ED25519_SECRETKEYBYTES];

        publicKeyCurve25519 = new byte[Sign.CURVE25519_PUBLICKEYBYTES];
        secretKeyCurve25519 = new byte[Sign.CURVE25519_SECRETKEYBYTES];

        int status = sodium.crypto_sign_keypair(publicKeyED25519, secretKeyED25519);
        status = sodium.crypto_sign_ed25519_pk_to_curve25519(publicKeyCurve25519, publicKeyED25519);
        status = sodium.crypto_sign_ed25519_sk_to_curve25519(secretKeyCurve25519, secretKeyED25519);
    }

    public String getPublicKeyED25519AsString() {
        // Hex string to byte[]
        // String pubKeyStr = "FACE42 ... DEC0DE";
        // byte[] buf = LazySodium.toBin(pubKeyStr);
        return LazySodium.toHex(publicKeyED25519);
    }

    public boolean verifyKexJson(String kex) throws JSONException, SodiumException {
        JSONObject json = new JSONObject(kex);
        String pk = json.getString("pk");
        String hash = json.getString("hash");

        byte[] ed25519 = LazySodium.toBin(pk);
        byte[] curve25519 = new byte[Sign.CURVE25519_PUBLICKEYBYTES];
        if (0 != sodium.crypto_sign_ed25519_pk_to_curve25519(curve25519, ed25519)) {
            throw new SodiumException("error: ED25519 to Curve25519 Conversion");
        }

        DiffieHellman.Lazy dh = (DiffieHellman.Lazy)lazySodium;
        Key publicKey = Key.fromBytes(curve25519);
        Key secretKey = Key.fromBytes(secretKeyCurve25519);
        Key sharedKey = dh.cryptoScalarMult(secretKey, publicKey);

        String computedHash = lazySodium.cryptoGenericHash(pk, sharedKey);
        return computedHash.equals(hash);
    }

    public String createKexJson(String myPubKey, String peerPubKey) throws JSONException, SodiumException {
        byte[] ed25519 = LazySodium.toBin(peerPubKey);
        byte[] curve25519 = new byte[Sign.CURVE25519_PUBLICKEYBYTES];
        if (0 != sodium.crypto_sign_ed25519_pk_to_curve25519(curve25519, ed25519)) {
            throw new SodiumException("error: ED25519 to Curve25519 Conversion");
        }

        DiffieHellman.Lazy dh = (DiffieHellman.Lazy)lazySodium;
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

    public String encrypt(String uin, String pubkeyED25519) throws JSONException, SodiumException {
        DiffieHellman.Lazy dh = (DiffieHellman.Lazy)lazySodium;
        SecretBox.Lazy box = (SecretBox.Lazy)lazySodium;
        Key publicKey = Key.fromHexString(edPub2curvePub(pubkeyED25519));
        Key secretKey = Key.fromBytes(secretKeyCurve25519);
        Key sharedKey = dh.cryptoScalarMult(secretKey, publicKey);

        byte[] nonce = lazySodium.nonce(Box.NONCEBYTES);
        JSONObject json = new JSONObject();
        String euin = box.cryptoSecretBoxEasy(uin, nonce, sharedKey);
        json.put("type", "msg");
        json.put("euin", euin);
        json.put("nonce", LazySodium.toHex(nonce));
        json.put("pk", LazySodium.toHex(publicKeyED25519));

        return json.toString();
    }

    public String decrypt(String jsonPayload) throws JSONException, SodiumException {
        DiffieHellman.Lazy dh = (DiffieHellman.Lazy)lazySodium;
        SecretBox.Lazy box = (SecretBox.Lazy)lazySodium;

        JSONObject json = new JSONObject(jsonPayload);
        String pubkey = json.get("pk").toString();

        byte[] ed25519 = LazySodium.toBin(pubkey);
        byte[] curve25519 = new byte[Sign.CURVE25519_PUBLICKEYBYTES];
        if (0 != sodium.crypto_sign_ed25519_pk_to_curve25519(curve25519, ed25519)) {
            throw new SodiumException("error: ED25519 to Curve25519 conversion");
        }

        byte[] nonce = LazySodium.toBin(json.get("nonce").toString());
        String euin = json.get("euin").toString();
        Key publicKey = Key.fromBytes(curve25519);

        Key secretKey = Key.fromBytes(secretKeyCurve25519);
        Key sharedKey = dh.cryptoScalarMult(secretKey, publicKey);
        String uin = box.cryptoSecretBoxOpenEasy(euin, nonce, sharedKey);

        return uin;
    }

    // Debug key pair to bypass QR code and debug Bluetooth
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

    private String edPub2curvePub(String edPub) throws SodiumException {
        byte[] ed25519 = LazySodium.toBin(edPub);
        byte[] curve25519 = new byte[Sign.CURVE25519_PUBLICKEYBYTES];
        if (0 != sodium.crypto_sign_ed25519_pk_to_curve25519(curve25519, ed25519)) {
            throw new SodiumException("error: ED25519 to Curve25519 conversion");
        }
        return LazySodium.toHex(curve25519);
    }
}
