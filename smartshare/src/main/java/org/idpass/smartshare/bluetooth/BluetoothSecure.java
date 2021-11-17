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

import android.app.Activity;
import android.util.Log;

import androidx.annotation.NonNull;

import com.google.android.gms.nearby.Nearby;
import com.google.android.gms.nearby.connection.AdvertisingOptions;
import com.google.android.gms.nearby.connection.ConnectionInfo;
import com.google.android.gms.nearby.connection.ConnectionLifecycleCallback;
import com.google.android.gms.nearby.connection.ConnectionResolution;
import com.google.android.gms.nearby.connection.ConnectionsClient;
import com.google.android.gms.nearby.connection.DiscoveredEndpointInfo;
import com.google.android.gms.nearby.connection.DiscoveryOptions;
import com.google.android.gms.nearby.connection.EndpointDiscoveryCallback;
import com.google.android.gms.nearby.connection.Payload;
import com.google.android.gms.nearby.connection.PayloadCallback;
import com.google.android.gms.nearby.connection.PayloadTransferUpdate;
import com.google.android.gms.nearby.connection.Strategy;
import com.goterl.lazysodium.exceptions.SodiumException;

import org.json.JSONException;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;

public class BluetoothSecure {

    @FunctionalInterface
    public interface LogCallback {
        void invoke(String msg);
    }

    @FunctionalInterface
    public interface NearbyCallback {
        void invoke(String msg);
    }

    @FunctionalInterface
    public interface ConnectionCreatedCallback {
        void invoke();
    }

    @FunctionalInterface
    public interface SendCallback {
        void invoke();
    }

    private final String transferUpdate[] = new String[]{"SUCCESS", "FAILURE", "IN_PROGRESS", "CANCELED"};

    private static final String TAG = BluetoothSecure.class.getName();
    private final String codeName = "residentapp";
    private String receiverName;
    private String receiverEndpointId;
    private String connectionId;
    private boolean doKex;
    private String peerPublicKey;
    private String btMode;

    private LogCallback onLogCallback = null;
    private NearbyCallback onNearbyCallback = null;
    private ConnectionCreatedCallback onConnectionCreatedCallback = null;
    private SendCallback onSendCallback = null;
    private ConnectionsClient link;

    private EncryptionUtils encryptionUtils;

    ////////////////////////////
    //  Received payload handler
    ////////////////////////////
    private final PayloadCallback payloadHandler = new PayloadCallback() {
        @Override
        public void onPayloadReceived(@NonNull String endpointId, @NonNull Payload payload) {
            Log.d(TAG,"onPayloadReceived:" + endpointId);
            if (payload.getType() == Payload.Type.BYTES) {
                String msg = new String(payload.asBytes(), StandardCharsets.UTF_8);
                emitEventLog("onPayloadReceived:" + endpointId);
                handleMessage(msg);
            } else {
                emitEventLog("Warning: onPayloadReceived not Type.BYTES");
            }
        }

        @Override
        public void onPayloadTransferUpdate(@NonNull String endpointId, @NonNull PayloadTransferUpdate payloadTransferUpdate) {
            int status = payloadTransferUpdate.getStatus();
            Log.d(TAG,String.format("onPayloadTransferUpdate:%s/%d", endpointId, status));
            emitEventLog(String.format("onPayloadTransferUpdate:%s/%d", endpointId, status));
            emitEventNearby(Utils.eventJson("transferupdate", transferUpdate[status - 1]));

            if (status == PayloadTransferUpdate.Status.SUCCESS) {
                if (onSendCallback != null) {
                    onSendCallback.invoke();
                    onSendCallback = null;
                }
            }
        }
    };

    private void emitEventLog(String s) {
        if (onLogCallback != null) {
            onLogCallback.invoke(s);
        }
    }

    private void emitEventNearby(String s) {
        if (onNearbyCallback != null) {
            onNearbyCallback.invoke(s);
        }
    }

    /////////////////////////////
    // Discovered devices handler
    /////////////////////////////
    private final EndpointDiscoveryCallback discoveryHandler = new EndpointDiscoveryCallback() {
        @Override
        public void onEndpointFound(@NonNull String endpointId, @NonNull DiscoveredEndpointInfo discoveredEndpointInfo) {
            Log.d(TAG, "onEndpointFound: " + endpointId);
            emitEventLog("onEndpointFound: " + endpointId);
            emitEventNearby(Utils.eventJson("onEndpointFound", endpointId));
            link.requestConnection(codeName, endpointId, lifecycleHandler);
        }

        @Override
        public void onEndpointLost(@NonNull String endpoint) {
            Log.d(TAG, "onEndpointLost: " + endpoint);
            emitEventLog("onEndpointLost: " + endpoint);
            emitEventNearby(Utils.eventJson("onEndpointLost", endpoint));
        }
    };

    ///////////////////////////////////
    // Connection/disconnection handler
    ///////////////////////////////////
    private final ConnectionLifecycleCallback lifecycleHandler = new ConnectionLifecycleCallback() {
        @Override
        public void onConnectionInitiated(@NonNull String endpointId, @NonNull ConnectionInfo connectionInfo) {
            Log.d(TAG, "onConnectionInitiated: " + endpointId);
            emitEventLog("onConnectionInitiated: " + endpointId);
            link.acceptConnection(endpointId, payloadHandler);
            receiverName = connectionInfo.getEndpointName();
        }

        @Override
        public void onConnectionResult(@NonNull String endpointId, @NonNull ConnectionResolution result) {
            Log.d(TAG, "onConnectionResult: " + endpointId);
            if (result.getStatus().isSuccess()) {
                link.stopDiscovery();
                link.stopAdvertising();
                receiverEndpointId = endpointId;

                if (onConnectionCreatedCallback != null) {
                    onConnectionCreatedCallback.invoke();
                    onConnectionCreatedCallback = null;
                }

                if (doKex) {
                    doKex = false;
                    sendPublicKey();
                }

                emitEventLog("onConnectionResult:success");
            } else {
                Log.d(TAG, "onConnectionResult: failed");
                emitEventLog("onConnectionResult: failed");

                link.stopDiscovery();
                link.stopAdvertising();
                startMode(btMode);
            }
        }

        @Override
        public void onDisconnected(@NonNull String endpointId) {
            Log.d(TAG, "onDisconnected: " + endpointId);
            emitEventLog("onDisconnected");
            emitEventNearby(Utils.eventJson("onDisconnected",endpointId));
        }
    };

    public BluetoothSecure() {
        encryptionUtils = new EncryptionUtils();
    }

    public void init(Activity activity, LogCallback logCallback, NearbyCallback nearbyCallback) {
        emitEventLog("BluetoothSecure::init"); // logger not yet
        link = Nearby.getConnectionsClient(activity);
        onLogCallback = logCallback;
        onNearbyCallback = nearbyCallback;
        onConnectionCreatedCallback = null;
        onSendCallback = null;
    }

    private void handleMessage(String msg) {
        try {
            JSONObject msgObj = new JSONObject(msg);
            String type = msgObj.get("type").toString();
            emitEventLog("handleMessage:" + type);
            switch (type) {
                case "msg":
                String uin = encryptionUtils.decrypt(msg);
                emitEventNearby(Utils.eventJson("msg", uin));
                break;

                case "kex":
                if (encryptionUtils.verifyKexJson(msg)) {
                    String pk = msgObj.get("pk").toString();
                    // emitEventNearby(Utils.eventJson("kex", pk));
                    this.peerPublicKey = pk;
                    emitEventLog("kex success");
                } else {
                    emitEventLog("kex fail");
                }
                break;

                default:
                emitEventLog("not handleMessage: " + type);
                break;
            }
        } catch (JSONException e) {
            emitEventLog("error: handleMessage json");
        } catch (SodiumException e) {
            emitEventLog("error handleMessage sodium");
        }
    }

    private void sendPublicKey()
    {
        emitEventLog("sendPublicKey");
        String publicKeyStr = encryptionUtils.getPublicKeyED25519AsString();
        try {
            String kexJson = encryptionUtils.createKexJson(publicKeyStr, peerPublicKey);
            link.sendPayload(receiverEndpointId,
                Payload.fromBytes(kexJson.getBytes(StandardCharsets.UTF_8)));
        } catch (JSONException | SodiumException e) {
            emitEventLog("sendPublicKey error");
        }
    }

    private boolean startMode(String mode) {
        boolean flag = false;
        emitEventLog("createConnection:" + mode + "/" + connectionId);
        switch (mode) {
            case "dual":
                link.startAdvertising(codeName,
                    connectionId, lifecycleHandler,
                    new AdvertisingOptions.Builder().setStrategy(Strategy.P2P_POINT_TO_POINT).build());

                link.startDiscovery(
                    connectionId, discoveryHandler,
                    new DiscoveryOptions.Builder().setStrategy(Strategy.P2P_POINT_TO_POINT).build());
                flag = true;
                break;

            case "discoverer":
                link.startDiscovery(
                    connectionId, discoveryHandler,
                    new DiscoveryOptions.Builder().setStrategy(Strategy.P2P_POINT_TO_POINT).build());
                flag = true;
                break;

            case "advertiser":
                link.startAdvertising(codeName,
                    connectionId, lifecycleHandler,
                    new AdvertisingOptions.Builder().setStrategy(Strategy.P2P_POINT_TO_POINT).build());
                flag = true;
                break;

            default:
                emitEventLog("createConnection:unknown");
                break;
        }

        return flag;
    }

    // APIs

    public String getConnectionParameters() {
        emitEventLog("getConnectionParameters");
        JSONObject json = new JSONObject();
        try {
            encryptionUtils.regenerateKeyPair();
            String publicKeyStr = encryptionUtils.getPublicKeyED25519AsString();
            String cid = Utils.getRandomString(5);
            json.put("cid", cid);
            json.put("pk",publicKeyStr);
            this.connectionId = cid;
            doKex = false;
            return json.toString();
        } catch (JSONException e) {
            emitEventLog(e.getMessage());
        }

        return "";
    }

    public void setConnectionParameters(String params) {
        emitEventLog("setConnectionParameters"); // logger not yet binded
        try {
            JSONObject json = new JSONObject(params);
            encryptionUtils.regenerateKeyPair();
            doKex = true;
            if (json.has("cid")) {
                Log.d(TAG, "*** cid set ***");
                this.connectionId = json.get("cid").toString();
            }
            if (json.has("pk")) {
                Log.d(TAG, "*** peerPk set ***");
                this.peerPublicKey = json.get("pk").toString();
            }
            Log.d(TAG, "*** setConnectionParameters done ***");
        } catch (JSONException e) {
            emitEventLog(e.getMessage());
            Log.d(TAG, e.getMessage());
        }
    }

    public String getConnectionParametersDebug() {
        JSONObject json = new JSONObject();
        try {
            encryptionUtils.regenerateKeyPairDebug();
            String publicKeyStr = encryptionUtils.getPublicKeyED25519AsString();
            json.put("cid", "id3nt");
            json.put("pk",publicKeyStr);
            doKex = false;
            return json.toString();
        } catch (JSONException e) {
            emitEventLog(e.getMessage());
        }

        return "";
    }

    public boolean createConnection(String mode, ConnectionCreatedCallback callback) {
        Log.d(TAG, "[+createConnection]");
        onConnectionCreatedCallback = callback;
        btMode = mode;
        return startMode(mode);
    }

    public void send(String msg, SendCallback callback) {
        emitEventLog("send");
        onSendCallback = callback;
        try {
            if (peerPublicKey != null && peerPublicKey.length()> 0) {
                String encrypted = encryptionUtils.encrypt(msg, peerPublicKey);
                link.sendPayload(receiverEndpointId,
                    Payload.fromBytes(encrypted.getBytes(StandardCharsets.UTF_8)));
            } else {
                emitEventLog("error peerPublicKey");
            }
        } catch (JSONException e) {
            emitEventLog(e.getMessage());
        } catch (SodiumException e) {
            emitEventLog(e.getMessage());
        }
    }

    public void destroyConnection() {
        emitEventLog("destroyConnection");
        link.disconnectFromEndpoint(receiverEndpointId);
        link.stopAllEndpoints();
        peerPublicKey = null;
    }
}
