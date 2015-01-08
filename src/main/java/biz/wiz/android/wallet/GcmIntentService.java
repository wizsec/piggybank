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
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptChunk;
import org.bitcoinj.uri.BitcoinURI;
import org.bitcoinj.uri.BitcoinURIParseException;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

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
                Log.i(TAG, "Received tx " + extras.getString("tx"));
                Transaction transaction = new Transaction(MainNetParams.get(), hexStringToByteArray(extras.getString("tx"))); // Update network parameters to global setting
                Log.i(TAG, "Received tx hash " + transaction.getHashAsString());

                signTransaction(transaction);

                Log.i(TAG, "New tx hash " + transaction.getHashAsString());
                Log.i(TAG, "New tx " + byteArrayToHex(transaction.bitcoinSerialize()));

                // Post notification of received message.
                // sendNotification(extras.getString("address"), prepareSendIntent(address, amount));
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

    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private void signTransaction(Transaction spendTx)
    {
        List<TransactionInput> inputList = spendTx.getInputs();
        Iterator<TransactionInput> inputIterator = inputList.iterator();
        String inputAddress = "";
        int i=0;

        while (inputIterator.hasNext())
        {
            TransactionInput inputToBeSigned = inputIterator.next();
            // Get the input chunks
            Script inputScript = inputToBeSigned.getScriptSig();
            List<ScriptChunk> scriptChunks = inputScript.getChunks();

            // Create a list of all signatures. Start by extracting the existing ones from the list of script schunks.
            // The last signature in the script chunk list is the redeemScript
            List<TransactionSignature> signatureList = new ArrayList<TransactionSignature>();
            Iterator<ScriptChunk> iterator = scriptChunks.iterator();
            Script redeemScript = null;

            while (iterator.hasNext())
            {
                ScriptChunk chunk = iterator.next();
                System.out.println(chunk.toString());
                System.out.println(iterator.hasNext());

                if (iterator.hasNext() && chunk.opcode != 0)
                {
                    TransactionSignature transactionSignarture = TransactionSignature.decodeFromBitcoin(chunk.data, false);
                    signatureList.add(transactionSignarture);
                } else
                {
                    redeemScript = new Script(chunk.data);
                }
            }

            // Create the sighash using the redeem script
            Sha256Hash sighash = spendTx.hashForSignature(i, redeemScript, Transaction.SigHash.ALL, false);
            ECKey.ECDSASignature secondSignature;

            // Take out the key and sign the signhash
            ECKey key2 = createKeyFromSha256Passphrase("Super secret key 2");
            secondSignature = key2.sign(sighash);

            // Add the second signature to the signature list
            TransactionSignature transactionSignature = new TransactionSignature(secondSignature, Transaction.SigHash.ALL, false);
            signatureList.add(transactionSignature);

            // Rebuild p2sh multisig input script
            inputScript = ScriptBuilder.createP2SHMultiSigInputScript(signatureList, redeemScript);
            spendTx.getInput(i).setScriptSig(inputScript);
            i++;
        }
    }

    /**
     * Method to convert a passphrase similar to brainwallet.org, to a bitcoin private key. This method of creating an ECKey is deprecated
     * @param secret
     * @return
     */
    public static ECKey createKeyFromSha256Passphrase(String secret) {
        byte[] hash = null;

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(secret.getBytes("UTF-8"));
            hash = md.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        @SuppressWarnings("deprecation")
        ECKey key = new ECKey(hash, (byte[])null);
        return key;
    }

    private String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for(byte b: a)
            sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }
}
