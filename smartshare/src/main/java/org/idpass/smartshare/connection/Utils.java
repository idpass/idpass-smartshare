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

import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Some common generic utility functions
 */
public class Utils {
    private static final String TAG = Utils.class.getName();

    static public void pause(int nsec) {
        int pauseSeconds = nsec;
        // Randomize it if not supplied
        if (pauseSeconds <= 0) {
            SecureRandom ran = new SecureRandom();
            pauseSeconds = 9 + ran.nextInt(30);
            Log.d(TAG, "pause " + pauseSeconds);
        }

        try {
            Thread.sleep(1000 * pauseSeconds);
        } catch (InterruptedException e) {
            e.printStackTrace();
            Log.e(TAG, "*** SLEEP ERROR ANOMALY ***");
        }
    }

    static String getRandomString(int len) {
        String SALTCHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder salt = new StringBuilder();
        SecureRandom rnd = new SecureRandom();
        while (salt.length() < len) { // length of the random string.
            int index = (int) (rnd.nextFloat() * SALTCHARS.length());
            salt.append(SALTCHARS.charAt(index));
        }
        String saltStr = salt.toString();
        return saltStr;
    }

    static public String eventJson(String type, String data) {
        JSONObject event = new JSONObject();
        try {
            event.put("type", type);
            event.put("data", data);
        } catch (JSONException e) {
        }
        return event.toString();
    }

    /**
     * Splits a huge payload into chunks of 31768 bytes each.
     *
     * @param payload A huge payload.
     * @return Returns a list of chunks of payload.
     */
    static public List<String> splitPayload(String payload) {
        int size = 31768;
        int n = (payload.length() + size - 1) / size;
        List<String> chunks = new ArrayList<String>(n);
        for (int start = 0; start < payload.length(); start += size) {
            chunks.add(payload.substring(start, Math.min(payload.length(), start + size)));
        }
        return chunks;
    }

    /**
     * Calculates the hash.
     *
     * @param text The text data to compute a hash from
     * @return Returns the hash of text
     */
    static public String computeHash(String text) {
        MessageDigest hash = null;
        try {
            hash = MessageDigest.getInstance("SHA-256");
            hash.update(text.getBytes());
            byte[] buf = hash.digest(); // echo -ne 'apple' | sha256sum
            return toHexString(buf);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Converts a hex byte array into its string representation.
     *
     * @param byteArray The hex byte array
     * @return Returns the hex string representation of the byte array
     */
    static public String toHexString(byte[] byteArray) {
        StringBuffer hexStringBuffer = new StringBuffer();
        for (int i = 0; i < byteArray.length; i++) {
            hexStringBuffer.append(byteToHex(byteArray[i]));
        }
        return hexStringBuffer.toString();
    }

    /**
     * Converts a byte into its hex string representation.
     *
     * @param num A hex byte value.
     * @return Returns the hex string representation of num
     */
    static public String byteToHex(byte num) {
        char[] hexDigits = new char[2];
        hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
        hexDigits[1] = Character.forDigit((num & 0xF), 16);
        return new String(hexDigits);
    }
}
