/*
 * Copyright (c) 2012-2016 Arne Schwabe
 * Distributed under the GNU GPL v2 with additional terms. For full terms see the file doc/LICENSE.txt
 * Modified by Mobile-IT
 */
package de.blinkt.openvpn.core;

import android.annotation.TargetApi;
import android.app.Application;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.os.Build;

import pl.mobit.jobtodoopenvpn.R;
import pl.mobit.jobtodoopenvpn.Utils;

public class App extends Application {

    @Override
    public void onCreate() {
        super.onCreate();
        PRNGFixes.apply();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            createNotificationChannels();
        }
        StatusListener mStatus = new StatusListener();
        mStatus.init(getApplicationContext());
    }

    @TargetApi(Build.VERSION_CODES.O)
    private void createNotificationChannels() {
        NotificationManager mNotificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        NotificationChannel mChannel = new NotificationChannel(Utils.CHANNEL_VPN_SERVICE, getString(R.string.vpn_channel_name),
                NotificationManager.IMPORTANCE_LOW);
        assert mNotificationManager != null;
        mNotificationManager.createNotificationChannel(mChannel);
    }
}
