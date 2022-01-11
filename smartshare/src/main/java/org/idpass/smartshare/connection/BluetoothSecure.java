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
import java.util.NoSuchElementException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingDeque;

/**
 * The transport layer that is secured by Android's Nearby implementation.
 * The payload is secured by Libsodium's cryptographic library.
 */
public class BluetoothSecure {

    public enum Mode {
        advertiser,
        discoverer,
        dual
    }

    public enum Event {
        ONENDPOINTFOUND,
        ONENDPOINTLOST,
        ONCONNECTIONINITIATED,
        ONCONNECTIONRESULT_SUCCESS,
        ONCONNECTIONRESULT_FAILED,
        ONDISCONNECTED,
        ONTRANSFER_BEGIN,
        ONTRANSFER_INPROGRESS,
        ONUPDATEINFO,
        ONSENT,
        ONRECEIVED
    }

    @FunctionalInterface
    public interface ConnectionEvent {
        void invoke(Event event, String info);
    }

    @FunctionalInterface
    public interface LogCallback {
        void invoke(String msg);
    }

    @FunctionalInterface
    public interface NearbyCallback {
        void invoke(String msg);
    }

    private static final String TAG = BluetoothSecure.class.getName();
    private final String codeName = "residentapp";
    private String receiverName;
    private String receiverEndpointId;
    private String connectionId;
    private boolean doKex;
    private String peerPublicKey;
    private Mode btMode;

    private LogCallback onLogCallback = null;
    private NearbyCallback onNearbyCallback = null;
    private ConnectionsClient link;

    private EncryptionUtils encryptionUtils;

    private ConnectionEvent allEvent = null;
    private ConnectionEvent transferEvent = null;

    private BlockingQueue<JSONObject> outbound = new LinkedBlockingDeque<>();
    private StringBuilder inbound = new StringBuilder();
    private String receivedChunk;

    ////////////////////////////
    //  Received payload handler
    ////////////////////////////
    private final PayloadCallback payloadHandler = new PayloadCallback() {
        @Override
        public void onPayloadReceived(@NonNull String endpointId, @NonNull Payload payload) {
            Log.d(TAG, "onPayloadReceived:" + endpointId);
            if (payload.getType() == Payload.Type.BYTES) {
                receivedChunk = new String(payload.asBytes(), StandardCharsets.UTF_8);
            }
        }

        @Override
        public void onPayloadTransferUpdate(@NonNull String endpointId, @NonNull PayloadTransferUpdate payloadTransferUpdate) {
            int status = payloadTransferUpdate.getStatus();

            switch (status) {
                case PayloadTransferUpdate.Status.SUCCESS:
                    if (receivedChunk != null) {
                        handleReceivedMessage(receivedChunk);
                        receivedChunk = null;
                    } else {
                        continueTransmitMessageChunks();
                    }
                    break;

                case PayloadTransferUpdate.Status.FAILURE:
                    emitEventNearby(Utils.eventJson("transferupdate", "-1.0"));
                    break;

                case PayloadTransferUpdate.Status.CANCELED:
                    emitEventNearby(Utils.eventJson("transferupdate", "-2.0"));
                    break;
            }

        }
    };

    /**
     * Propagates debugging messages to the application.
     *
     * @param s A debug message
     */
    private void emitEventLog(String s) {
        if (onLogCallback != null) {
            onLogCallback.invoke(s);
        }
    }

    /**
     * Propagates Bluetooth events to the application.
     *
     * @param s A json structured event object
     */
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
            emitEvent(Event.ONENDPOINTFOUND, null);
            link.requestConnection(codeName, endpointId, lifecycleHandler);
        }

        @Override
        public void onEndpointLost(@NonNull String endpoint) {
            Log.d(TAG, "onEndpointLost: " + endpoint);
            emitEventLog("onEndpointLost: " + endpoint);
            emitEventNearby(Utils.eventJson("onEndpointLost", endpoint));
            emitEvent(Event.ONENDPOINTLOST, null);
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
            emitEvent(Event.ONCONNECTIONINITIATED, null);
        }

        @Override
        public void onConnectionResult(@NonNull String endpointId, @NonNull ConnectionResolution result) {
            Log.d(TAG, "onConnectionResult: " + endpointId);

            link.stopDiscovery();
            link.stopAdvertising();

            if (result.getStatus().isSuccess()) {
                receiverEndpointId = endpointId;
                emitEvent(Event.ONCONNECTIONRESULT_SUCCESS, null);
                if (doKex) {
                    doKex = false;
                    sendPublicKey();
                }
                emitEventLog("onConnectionResult:success");
            } else {
                Log.d(TAG, "onConnectionResult: failed");
                emitEventLog("onConnectionResult: failed");
                emitEvent(Event.ONCONNECTIONRESULT_FAILED, null);
                startMode(btMode);
            }
        }

        @Override
        public void onDisconnected(@NonNull String endpointId) {
            Log.d(TAG, "onDisconnected: " + endpointId);
            emitEventLog("onDisconnected");
            emitEventNearby(Utils.eventJson("onDisconnected", endpointId));
            emitEvent(Event.ONDISCONNECTED, null);
        }
    };

    public BluetoothSecure() {
        encryptionUtils = new EncryptionUtils();
    }

    /**
     * Initialization method to set an Activity and callback functions.
     *
     * @param activity       The main application's Activity object
     * @param logCallback    Callback function to handle log messages for debug tracing
     * @param nearbyCallback Callback function to handle Bluetooth events
     */
    public void init(Activity activity, LogCallback logCallback, NearbyCallback nearbyCallback) {
        emitEventLog("BluetoothSecure::init"); // logger not yet
        link = Nearby.getConnectionsClient(activity);
        onLogCallback = logCallback;
        onNearbyCallback = nearbyCallback;
    }

    /**
     * Part of the key exchange handshake to exchange a
     * key hashed public key to remote peer. This happens
     * at connection creation.
     */
    private void sendPublicKey() {
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

    /**
     * Starts/restarts the Bluetooth signalling based on mode.
     *
     * @param mode The type of signalling mode to use.
     * @return Returns true if the signalling has started
     */
    private void startMode(Mode mode) {
        emitEventLog("createConnection:" + mode + "/" + connectionId);
        switch (mode) {
            case dual:
                link.startAdvertising(codeName,
                        connectionId, lifecycleHandler,
                        new AdvertisingOptions.Builder().setStrategy(Strategy.P2P_POINT_TO_POINT).build());

                link.startDiscovery(
                        connectionId, discoveryHandler,
                        new DiscoveryOptions.Builder().setStrategy(Strategy.P2P_POINT_TO_POINT).build());
                break;

            case discoverer:
                link.startDiscovery(
                        connectionId, discoveryHandler,
                        new DiscoveryOptions.Builder().setStrategy(Strategy.P2P_POINT_TO_POINT).build());
                break;

            case advertiser:
                link.startAdvertising(codeName,
                        connectionId, lifecycleHandler,
                        new AdvertisingOptions.Builder().setStrategy(Strategy.P2P_POINT_TO_POINT).build());
                break;
        }
    }

    // APIs

    /**
     * API used to generate a randomized Bluetooth connectionId and
     * ED25519 key pair.
     *
     * @return
     */
    public String getConnectionParameters() {
        emitEventLog("getConnectionParameters");
        JSONObject json = new JSONObject();
        try {
            encryptionUtils.regenerateKeyPair();
            String publicKeyStr = encryptionUtils.getPublicKeyED25519AsString();
            String cid = Utils.getRandomString(5);
            json.put("cid", cid);
            json.put("pk", publicKeyStr);
            this.connectionId = cid;
            doKex = false;
            return json.toString();
        } catch (JSONException e) {
            emitEventLog(e.getMessage());
        }

        return "";
    }

    /**
     * API used to set a specific connectionId. This also
     * re-generates the underlying ED25519 key pair.
     *
     * @param params The target Bluetooth connection ID
     */
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

    /**
     * This is for debugging purposes only. It is used to quickly setup
     * the Bluetooth connection ID and ED25519 key pairs for testing purposes.
     *
     * @return Returns a pre-defined connection code parameters
     */
    public String getConnectionParametersDebug() {
        JSONObject json = new JSONObject();
        try {
            encryptionUtils.regenerateKeyPairDebug();
            String publicKeyStr = encryptionUtils.getPublicKeyED25519AsString();
            json.put("cid", "id3nt");
            json.put("pk", publicKeyStr);
            doKex = false;
            return json.toString();
        } catch (JSONException e) {
            emitEventLog(e.getMessage());
        }

        return "";
    }

    /**
     * Once the connection parameters are acquired and set, the next
     * phase is to attempt to establish an RF link on top of which
     * a connection shall be created.
     *
     * @param mode     The Bluetooth signalling mode during RF link establishment
     * @param callback This callback will be invoked when a connection is successfully created.
     * @return Returns true if the signalling is in-progress
     */
    public void createConnection(Mode mode, ConnectionEvent callback) {
        Log.d(TAG, "[+createConnection]");
        allEvent = callback;
        btMode = mode;
        startMode(mode);
    }

    /**
     * Sends a string message to the connected peer.
     *
     * @param msg      The plaintext message to send
     * @param callback This callback is invoked when the message is sent
     */
    public void send(String msg, ConnectionEvent callback) {
        transferEvent = callback;
        if (peerPublicKey != null) {
            outbound = encryptionUtils.chunkPayload(msg, peerPublicKey);
            continueTransmitMessageChunks();
        } else {
            try {
                JSONObject j = new JSONObject();
                j.put("error", "no peerPublicKey");
                emitEvent(Event.ONUPDATEINFO, j.toString());
            } catch (JSONException e) {}
        }
    }

    /**
     * Shuts down the RF link between the two devices, and
     * consequently destroys the connection between them.
     */
    public void destroyConnection() {
        emitEventLog("destroyConnection");
        link.disconnectFromEndpoint(receiverEndpointId);
        link.stopAllEndpoints();
        peerPublicKey = null;
    }

    /**
     * Pops out the chunks from the queue and transmits them individually.
     * This method also sends events.
     */
    private void continueTransmitMessageChunks() {
        try {
            JSONObject toSend = outbound.remove();
            String chunk = toSend.toString();
            String type = toSend.getString("type");

            switch (type) {
                case "begin":
                    emitEvent(Event.ONTRANSFER_BEGIN, chunk);
                    break;

                case "chunk":
                    emitEvent(Event.ONTRANSFER_INPROGRESS, chunk);
                    double p = toSend.getDouble("percent");
                    String percent = String.format("%f", p);
                    emitEventNearby(Utils.eventJson("transferupdate", percent));
                    break;

                case "end":
                    emitEvent(Event.ONSENT, null);
                    break;
            }

            link.sendPayload(receiverEndpointId,
                    Payload.fromBytes(chunk.getBytes(StandardCharsets.UTF_8)));

        } catch (NoSuchElementException | JSONException e) {
        }
    }

    private void emitEvent(Event event, String info) {
        if (allEvent != null) allEvent.invoke(event, info);
        if (transferEvent != null) {
            switch (event) {
                case ONTRANSFER_BEGIN:
                case ONTRANSFER_INPROGRESS:
                case ONSENT:
                case ONRECEIVED:
                    transferEvent.invoke(event, info);
                    break;
            }
        }
    }

    /**
     * Handles incoming received chunks of messages. It accumulates received
     * chunks into the inbound variable and emits an msg event to propagate
     * the completed received and decrypted payload. This method also handles the
     * special kex message type used to initialize the peer's public key.
     *
     * @param msg A chunk message.
     */
    private void handleReceivedMessage(String msg) {
        try {
            JSONObject msgObj = new JSONObject(msg);
            String type = msgObj.get("type").toString();

            switch (type) {
                case "begin":
                    inbound.setLength(0);
                    emitEvent(Event.ONTRANSFER_BEGIN, msgObj.toString());
                    break;

                case "chunk":
                    inbound.append(msgObj.getString("data"));
                    emitEvent(Event.ONTRANSFER_INPROGRESS, msgObj.toString());
                    double p = msgObj.getDouble("percent");
                    String percent = String.format("%f", p);
                    emitEventNearby(Utils.eventJson("transferupdate", percent));
                    break;

                case "end":
                    emitEvent(Event.ONRECEIVED, null);
                    if (inbound.length() > 0) {
                        try {
                            String decrypted = encryptionUtils.decryptInbound(inbound.toString(),
                                peerPublicKey, msgObj.getString("nonce"));
                            emitEventNearby(Utils.eventJson("msg", decrypted));
                        } catch (JSONException | SodiumException e) {
                            JSONObject j = new JSONObject();
                            j.put("error", "fail decryptInbound");
                            emitEvent(Event.ONUPDATEINFO, j.toString());
                        }
                    }
                    break;

                case "kex":
                    if (encryptionUtils.verifyKexJson(msg)) {
                        this.peerPublicKey = msgObj.get("pk").toString();
                    } else {
                        JSONObject j = new JSONObject();
                        j.put("error", "kex verify error");
                        emitEvent(Event.ONUPDATEINFO, j.toString());
                    }
                    break;
            }

        } catch (JSONException | SodiumException e) {

        }
    }
}
