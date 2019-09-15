package pl.mobit.jobtodoopenvpn;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.util.UUID;

import de.blinkt.openvpn.VpnProfile;
import de.blinkt.openvpn.core.ConfigParser;
import de.blinkt.openvpn.core.IOpenVPNServiceInternal;
import de.blinkt.openvpn.core.OpenVPNService;
import de.blinkt.openvpn.core.ProfileManager;
import de.blinkt.openvpn.core.VPNLaunchHelper;
import de.blinkt.openvpn.core.VpnStatus;

public class OpenVpnActivity extends Activity {

    private static final String TAG = "OpenVpnActivity";

    private boolean stop = false;
    public static UUID uuid;
    private VpnProfile vpnProfile;
    private IOpenVPNServiceInternal vpnService;
    private ServiceConnection vpnServiceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName className, IBinder service) {
            vpnService = IOpenVPNServiceInternal.Stub.asInterface(service);
            if(stop) {
                if (vpnService != null) {
                    try {
                        vpnService.stopVPN(false);
                    } catch (RemoteException e) {
                        returnError(e);
                    }
                }
                setResult(RESULT_OK);
                finish();
                stop = false;
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName arg0) {
            vpnService = null;
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_open_vpn);
        if(getIntent() != null && getIntent().hasExtra("uuid")) {
            String action = getIntent().getAction();
            if(action != null) {
                uuid = (UUID) getIntent().getSerializableExtra("uuid");
                switch (action) {
                    case Utils.ACTION_START_VPN:
                        if(getIntent().hasExtra("profile") || getIntent().hasExtra("config")) {
                            startVPN();
                        } else {
                            finish();
                        }
                        return;
                    case Utils.ACTION_STOP_VPN:
                        stopVPN();
                        return;
                }
            }
        }
        finish();
    }

    @Override
    protected void onResume() {
        super.onResume();
        Intent intent = new Intent(this, OpenVPNService.class);
        intent.setAction(OpenVPNService.START_SERVICE);
        bindService(intent, vpnServiceConnection, Context.BIND_AUTO_CREATE);
    }

    @Override
    protected void onPause() {
        super.onPause();
        unbindService(vpnServiceConnection);
    }

    private void startVPN() {
        try {
            vpnProfile = (VpnProfile) getIntent().getSerializableExtra("profile");
            if(vpnProfile == null) {
                ConfigParser cp = new ConfigParser();
                cp.parseConfig(new BufferedReader(new InputStreamReader(new ByteArrayInputStream(getIntent().getStringExtra("config").getBytes()))));
                VpnProfile vp = cp.convertProfile();
                vp.mName = Build.MODEL;
                if(getIntent().hasExtra("username")) {
                    vp.mUsername = getIntent().getStringExtra("username");
                    vp.mPassword = getIntent().getStringExtra("password");
                }
                if(getIntent().hasExtra("allow_pkg")) {
                    vp.mAllowedAppsVpn.add("pl.mobit.jobtodo");
                    vp.mAllowedAppsVpnAreDisallowed = false;
                }
                vpnProfile = vp;
            }

            VpnStatus.clearLog();

            if(vpnProfile == null) {
                Log.e(TAG, "VPN profile is null");
                returnMsg(null);
                return;
            }

            ProfileManager.setTemporaryProfile(this, vpnProfile);

            int profileStatus = vpnProfile.checkProfile(this);
            if(profileStatus != R.string.no_error_found) {
                returnMsg(getString(profileStatus));
                return;
            }

            Intent intent = VpnService.prepare(this);
            if(intent != null) {
                startActivityForResult(intent, Utils.START_VPN_REQUEST_CODE);
            } else {
                onActivityResult(Utils.START_VPN_REQUEST_CODE, Activity.RESULT_OK, null);
            }
        } catch (Exception e) {
            returnError(e);
        }
    }

    private void stopVPN() {
        stop = true;
        ProfileManager.setConntectedVpnProfileDisconnected(this);
        ProfileManager.removeTemporaryProfile(this);
    }

    private void returnError(Exception e) {
        e.printStackTrace();
        Intent data = new Intent();
        data.putExtra("e", e);
        setResult(2, data);
        finish();
    }

    private void returnMsg(String msg) {
        Intent data = new Intent();
        data.putExtra("msg", msg);
        setResult(2, data);
        finish();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if(requestCode == Utils.START_VPN_REQUEST_CODE) {
            if(resultCode == Activity.RESULT_OK) {
                int needPW = vpnProfile.needUserPWInput(null, null);
                if (needPW != 0) {
                    Log.w(TAG, "onActivityResult: Need password");
                    setResult(RESULT_CANCELED);
                    finish();
                } else {
                    VPNLaunchHelper.startOpenVpn(vpnProfile, getBaseContext());
                    setResult(RESULT_OK);
                    finish();
                }
            } else if (resultCode == Activity.RESULT_CANCELED) {
                setResult(RESULT_CANCELED);
                finish();
            } else {
                setResult(resultCode);
                finish();
            }
        }
    }
}
