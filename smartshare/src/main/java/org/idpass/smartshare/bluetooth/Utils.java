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

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Log;

import androidx.core.content.ContextCompat;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.Random;

public class Utils {
    private static final String TAG = Utils.class.getName();
    private static final int REQUEST_CODE_REQUIRED_PERMISSIONS = 1;

    private static final String[] REQUIRED_PERMISSIONS = new String[]{
            Manifest.permission.BLUETOOTH,
            Manifest.permission.BLUETOOTH_ADMIN,
            Manifest.permission.ACCESS_WIFI_STATE,
            Manifest.permission.CHANGE_WIFI_STATE,
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.WRITE_EXTERNAL_STORAGE,
            Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.ACCESS_FINE_LOCATION,
    };

    private static final String[] REQUIRED_PERMISSIONS_Q = new String[] {
            Manifest.permission.BLUETOOTH,
            Manifest.permission.BLUETOOTH_ADMIN,
            Manifest.permission.ACCESS_WIFI_STATE,
            Manifest.permission.CHANGE_WIFI_STATE,
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.WRITE_EXTERNAL_STORAGE,
            Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_BACKGROUND_LOCATION,
    };

    public static void checkPermissions(Activity activity) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            Log.d(TAG,"*** AAA");
            if (!hasPermissions(activity.getApplicationContext(), REQUIRED_PERMISSIONS_Q)) {
                Log.d(TAG,"*** BBB");
                activity.requestPermissions(REQUIRED_PERMISSIONS_Q, REQUEST_CODE_REQUIRED_PERMISSIONS);
            }
        } else {
            if (!hasPermissions(activity.getApplicationContext(), REQUIRED_PERMISSIONS)) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    Log.d(TAG,"*** CCC");
                    activity.requestPermissions(REQUIRED_PERMISSIONS, REQUEST_CODE_REQUIRED_PERMISSIONS);
                }
            }
        }
    }

    private static boolean hasPermissions(Context context, String... permissions) {
        for (String permission : permissions) {
            if (ContextCompat.checkSelfPermission(context, permission)
                    != PackageManager.PERMISSION_GRANTED)
            {
                return false;
            }
        }
        return true;
    }

    static public void pause(int nsec) {
        int pauseSeconds = nsec;
        // Randomize it if not supplied
        if (pauseSeconds  <= 0) {
            Random ran = new Random();
            pauseSeconds = 9 + ran.nextInt(30);
            Log.d(TAG,"pause " + pauseSeconds);
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
        Random rnd = new Random();
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
        } catch (JSONException e) {}
        return event.toString();
    }

}
