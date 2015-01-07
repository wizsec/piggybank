package biz.wiz.android.wallet;

/**
 * Created by magma on 2014-12-12.
 */
import com.google.android.gms.gcm.GoogleCloudMessaging;

import android.app.IntentService;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.SystemClock;
import android.support.v4.app.NotificationCompat;
import android.util.Log;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.uri.BitcoinURI;
import org.bitcoinj.uri.BitcoinURIParseException;

import biz.wiz.android.wallet.data.PaymentIntent;
import biz.wiz.android.wallet.ui.WalletActivity;
import biz.wiz.android.wallet.ui.send.SendCoinsActivity;
import biz.wiz.android.wallet_test.R;

/**
 * This {@code IntentService} does the actual handling of the GCM message.
 * {@code GcmBroadcastReceiver} (a {@code WakefulBroadcastReceiver}) holds a
 * partial wake lock for this service while the service does its work. When the
 * service is finished, it calls {@code completeWakefulIntent()} to release the
 * wake lock.
 */
public class GcmIntentService extends IntentService {
    public static final int NOTIFICATION_ID = 1;
    private NotificationManager mNotificationManager;
    NotificationCompat.Builder builder;
    public static final String TAG = "GCM Demo";

    public GcmIntentService() {
        super("GcmIntentService");
    }

    @Override
    protected void onHandleIntent(Intent intent) {
        Bundle extras = intent.getExtras();
        GoogleCloudMessaging gcm = GoogleCloudMessaging.getInstance(this);
        // The getMessageType() intent parameter must be the intent you received
        // in your BroadcastReceiver.
        String messageType = gcm.getMessageType(intent);

        if (!extras.isEmpty()) {  // has effect of unparcelling Bundle
            /*
             * Filter messages based on message type. Since it is likely that GCM will be
             * extended in the future with new message types, just ignore any message types you're
             * not interested in, or that you don't recognize.
             */
            if (GoogleCloudMessaging.MESSAGE_TYPE_SEND_ERROR.equals(messageType)) {
                sendNotification("Send error: " + extras.toString(), null);
            } else if (GoogleCloudMessaging.MESSAGE_TYPE_DELETED.equals(messageType)) {
                sendNotification("Deleted messages on server: " + extras.toString(), null);
                // If it's a regular GCM message, do some work.
            } else if (GoogleCloudMessaging.MESSAGE_TYPE_MESSAGE.equals(messageType)) {
                Log.i(TAG, "Got cloud message: " + extras.toString());
                // parse and log
                String address = extras.getString("address");
                Long amount = Long.valueOf(extras.getString("amount"));
                Log.i(TAG, "Received send request to " + address + " for " + amount + " satoshi");

                // Post notification of received message.
                sendNotification(extras.getString("address"), prepareSendIntent(address, amount));
            }
        }
        // Release the wake lock provided by the WakefulBroadcastReceiver.
        GcmBroadcastReceiver.completeWakefulIntent(intent);
    }

    private static final int SATOSHIS_PER_COIN = 100000000;

    private Intent prepareSendIntent(final String address, final Long amount)
    {
        try {
            // build bitcoin uri from arguments
            StringBuilder uri = new StringBuilder("bitcoin:");
            if (address != null)
                uri.append(address);
            if (amount != null)
                uri.append("?amount=").append(String.format("%d.%08d", amount / SATOSHIS_PER_COIN, amount % SATOSHIS_PER_COIN));

            // pass uri string to bitcoinj library
            BitcoinURI buri = new BitcoinURI(uri.toString());

            // convert bitcoinj object to intent data
            PaymentIntent paymentIntent = PaymentIntent.fromBitcoinUri(buri);

            // create intent
            Intent sendIntent = new Intent(this, SendCoinsActivity.class);
            // add payment data as extra
            sendIntent.putExtra(SendCoinsActivity.INTENT_EXTRA_PAYMENT_INTENT, paymentIntent);
            // set intent as new task
            sendIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

            return sendIntent;
        }
        catch (BitcoinURIParseException e)
        {
            Log.i(TAG, "Failed parsing send request to " + address + " for " + amount + " satoshi: " + e.toString());
        }

		return null;
    }

    // Put the message into a notification and post it.
    // This is just one simple example of what you might choose to do with
    // a GCM message.
    private void sendNotification(String msg, Intent sendIntent) {
        mNotificationManager = (NotificationManager)
                this.getSystemService(Context.NOTIFICATION_SERVICE);

        NotificationCompat.Builder mBuilder =
                new NotificationCompat.Builder(this)
                        .setSmallIcon(R.drawable.app_icon)
                        .setContentTitle("Signing request")
                        .setStyle(new NotificationCompat.BigTextStyle().bigText("Sign transaction to " + msg))
                        .setContentText("Sign transaction to " + msg);

        if (sendIntent != null)
        {
            PendingIntent contentIntent = PendingIntent.getActivity(this, 0, sendIntent, 0);
            mBuilder.setContentIntent(contentIntent);
        }

        mNotificationManager.notify(NOTIFICATION_ID, mBuilder.build());
    }
}
