/*
 * Copyright 2011-2014 the original author or authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package biz.wiz.android.wallet.ui;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.TimeZone;
import java.util.concurrent.atomic.AtomicInteger;

import javax.annotation.Nonnull;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.VerificationException;
import org.bitcoinj.core.VersionedChecksummedBytes;
import org.bitcoinj.core.Wallet;
import org.bitcoinj.core.Wallet.BalanceType;
import org.bitcoinj.store.WalletProtobufSerializer;
import org.bitcoinj.wallet.Protos;
import org.json.JSONObject;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.app.DownloadManager.Request;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnCancelListener;
import android.content.DialogInterface.OnClickListener;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.net.Uri;
import android.nfc.NdefMessage;
import android.nfc.NfcAdapter;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.text.Html;
import android.text.format.DateUtils;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GooglePlayServicesUtil;
import com.google.android.gms.gcm.GoogleCloudMessaging;
import com.google.common.base.Charsets;

import biz.wiz.android.wallet.Configuration;
import biz.wiz.android.wallet.Constants;
import biz.wiz.android.wallet.WalletApplication;
import biz.wiz.android.wallet.data.PaymentIntent;
import biz.wiz.android.wallet.ui.InputParser.BinaryInputParser;
import biz.wiz.android.wallet.ui.InputParser.StringInputParser;
import biz.wiz.android.wallet.ui.preference.PreferenceActivity;
import biz.wiz.android.wallet.ui.send.SendCoinsActivity;
import biz.wiz.android.wallet.ui.send.SweepWalletActivity;
import biz.wiz.android.wallet.util.CrashReporter;
import biz.wiz.android.wallet.util.Crypto;
import biz.wiz.android.wallet.util.HttpGetThread;
import biz.wiz.android.wallet.util.Io;
import biz.wiz.android.wallet.util.Iso8601Format;
import biz.wiz.android.wallet.util.Nfc;
import biz.wiz.android.wallet.util.WalletUtils;
import biz.wiz.android.wallet.util.WholeStringBuilder;
import biz.wiz.android.wallet_test.R;
import biz.wiz.android.wallet_test.SignTransactionActivity;

import com.loopj.android.http.*;

/**
 * @author Andreas Schildbach
 */
public final class WalletActivity extends AbstractWalletActivity
{
	private static final int DIALOG_RESTORE_WALLET = 0;
	private static final int DIALOG_BACKUP_WALLET = 1;
	private static final int DIALOG_TIMESKEW_ALERT = 2;
	private static final int DIALOG_VERSION_ALERT = 3;
	private static final int DIALOG_LOW_STORAGE_ALERT = 4;

	private WalletApplication application;
	private Configuration config;
	private Wallet wallet;

	private Handler handler = new Handler();

	private static final int REQUEST_CODE_SCAN = 0;

    public static final String EXTRA_MESSAGE = "message";
    public static final String PROPERTY_REG_ID = "registration_id";
    private static final String PROPERTY_APP_VERSION = "appVersion";
    private final static int PLAY_SERVICES_RESOLUTION_REQUEST = 9000;

    /**
     * Substitute you own sender ID here. This is the project number you got
     * from the API Console, as described in "Getting Started."
     */
    String SENDER_ID = "256020192693";

    /**
     * Tag used on log messages.
     */
    static final String TAG = "GCMDemo";

    GoogleCloudMessaging gcm;
    AtomicInteger msgId = new AtomicInteger();
    SharedPreferences prefs;
    Context context;

    String regid;

	@Override
	protected void onCreate(final Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);

        // Check device for Play Services APK. If check succeeds, proceed with
        //  GCM registration.
        if (checkPlayServices()) {
            gcm = GoogleCloudMessaging.getInstance(this);
            regid = getRegistrationId(context);

            if (regid.isEmpty()) {
                registerInBackground();
            }
        } else {
            Log.i(TAG, "No valid Google Play Services APK found.");
        }

		application = getWalletApplication();
		config = application.getConfiguration();
		wallet = application.getWallet();

		setContentView(R.layout.wallet_content);

		if (savedInstanceState == null)
			checkAlerts();

		config.touchLastUsed();

		handleIntent(getIntent());

		MaybeMaintenanceFragment.add(getFragmentManager());
	}

	@Override
	protected void onResume()
	{
		super.onResume();

		handler.postDelayed(new Runnable()
		{
			@Override
			public void run()
			{
				// delayed start so that UI has enough time to initialize
				getWalletApplication().startBlockchainService(true);
			}
		}, 1000);

		checkLowStorageAlert();
	}

	@Override
	protected void onPause()
	{
		handler.removeCallbacksAndMessages(null);

		super.onPause();
	}

	@Override
	protected void onNewIntent(final Intent intent)
	{
		handleIntent(intent);
	}

	private void handleIntent(@Nonnull final Intent intent)
	{
		final String action = intent.getAction();

		if (NfcAdapter.ACTION_NDEF_DISCOVERED.equals(action))
		{
			final String inputType = intent.getType();
			final NdefMessage ndefMessage = (NdefMessage) intent.getParcelableArrayExtra(NfcAdapter.EXTRA_NDEF_MESSAGES)[0];
			final byte[] input = Nfc.extractMimePayload(Constants.MIMETYPE_TRANSACTION, ndefMessage);

			new BinaryInputParser(inputType, input)
			{
				@Override
				protected void handlePaymentIntent(final PaymentIntent paymentIntent)
				{
					cannotClassify(inputType);
				}

				@Override
				protected void error(final int messageResId, final Object... messageArgs)
				{
					dialog(WalletActivity.this, null, 0, messageResId, messageArgs);
				}
			}.parse();
		}
	}

	@Override
	public void onActivityResult(final int requestCode, final int resultCode, final Intent intent)
	{
		if (requestCode == REQUEST_CODE_SCAN && resultCode == Activity.RESULT_OK)
		{
			final String input = intent.getStringExtra(ScanActivity.INTENT_EXTRA_RESULT);

			new StringInputParser(input)
			{
				@Override
				protected void handlePaymentIntent(@Nonnull final PaymentIntent paymentIntent)
				{
					SendCoinsActivity.start(WalletActivity.this, paymentIntent);
				}

				@Override
				protected void handlePrivateKey(@Nonnull final VersionedChecksummedBytes key)
				{
					SweepWalletActivity.start(WalletActivity.this, key);
				}

				@Override
				protected void handleDirectTransaction(final Transaction tx) throws VerificationException
				{
					application.processDirectTransaction(tx);
				}

				@Override
				protected void error(final int messageResId, final Object... messageArgs)
				{
					dialog(WalletActivity.this, null, R.string.button_scan, messageResId, messageArgs);
				}
			}.parse();
		}
	}

	@Override
	public boolean onCreateOptionsMenu(final Menu menu)
	{
		super.onCreateOptionsMenu(menu);

		getMenuInflater().inflate(R.menu.wallet_options, menu);
		menu.findItem(R.id.wallet_options_donate).setVisible(!Constants.TEST);

		return true;
	}

	@Override
	public boolean onPrepareOptionsMenu(final Menu menu)
	{
		super.onPrepareOptionsMenu(menu);

		final Resources res = getResources();
		final String externalStorageState = Environment.getExternalStorageState();

		menu.findItem(R.id.wallet_options_exchange_rates).setVisible(res.getBoolean(R.bool.show_exchange_rates_option));
		menu.findItem(R.id.wallet_options_restore_wallet).setEnabled(true);
		menu.findItem(R.id.wallet_options_backup_wallet).setEnabled(true);
		menu.findItem(R.id.wallet_options_encrypt_keys).setTitle(
				wallet.isEncrypted() ? R.string.wallet_options_encrypt_keys_change : R.string.wallet_options_encrypt_keys_set);

		return true;
	}

	@Override
	public boolean onOptionsItemSelected(final MenuItem item)
	{
		switch (item.getItemId())
		{
			case R.id.wallet_options_request:
				handleRequestCoins();
				return true;

			case R.id.wallet_options_send:
				handleSendCoins();
				return true;

			case R.id.wallet_options_scan:
				handleScan();
				return true;

			case R.id.wallet_options_address_book:
				AddressBookActivity.start(this);
				return true;

			case R.id.wallet_options_exchange_rates:
				startActivity(new Intent(this, ExchangeRatesActivity.class));
				return true;

			case R.id.wallet_options_sweep_wallet:
				SweepWalletActivity.start(this);
				return true;

			case R.id.wallet_options_network_monitor:
				startActivity(new Intent(this, NetworkMonitorActivity.class));
				return true;

			case R.id.wallet_options_restore_wallet:
				showDialog(DIALOG_RESTORE_WALLET);
				return true;

			case R.id.wallet_options_backup_wallet:
				handleBackupWallet();
				return true;

			case R.id.wallet_options_encrypt_keys:
				handleEncryptKeys();
				return true;

			case R.id.wallet_options_preferences:
				startActivity(new Intent(this, PreferenceActivity.class));
				return true;

			case R.id.wallet_options_safety:
				HelpDialogFragment.page(getFragmentManager(), R.string.help_safety);
				return true;

			case R.id.wallet_options_donate:
				handleDonate();
				return true;

			case R.id.wallet_options_help:
				HelpDialogFragment.page(getFragmentManager(), R.string.help_wallet);
				return true;
            case R.id.wallet_options_echo: {
                startActivity(new Intent(this, SignTransactionActivity.class));
                return true;
            }
		}

		return super.onOptionsItemSelected(item);
	}

	public void handleRequestCoins()
	{
		startActivity(new Intent(this, RequestCoinsActivity.class));
	}

	public void handleSendCoins()
	{
		startActivity(new Intent(this, SendCoinsActivity.class));
	}

	public void handleScan()
	{
		startActivityForResult(new Intent(this, ScanActivity.class), REQUEST_CODE_SCAN);
	}

	public void handleBackupWallet()
	{
		showDialog(DIALOG_BACKUP_WALLET);
	}

	public void handleEncryptKeys()
	{
		EncryptKeysDialogFragment.show(getFragmentManager());
	}

	private void handleDonate()
	{
		try
		{
			SendCoinsActivity.start(this, PaymentIntent.fromAddress(Constants.DONATION_ADDRESS, getString(R.string.wallet_donate_address_label)));
		}
		catch (final AddressFormatException x)
		{
			// cannot happen, address is hardcoded
			throw new RuntimeException(x);
		}
	}

	@Override
	protected Dialog onCreateDialog(final int id, final Bundle args)
	{
		if (id == DIALOG_RESTORE_WALLET)
			return createRestoreWalletDialog();
		else if (id == DIALOG_BACKUP_WALLET)
			return createBackupWalletDialog();
		else if (id == DIALOG_TIMESKEW_ALERT)
			return createTimeskewAlertDialog(args.getLong("diff_minutes"));
		else if (id == DIALOG_VERSION_ALERT)
			return createVersionAlertDialog();
		else if (id == DIALOG_LOW_STORAGE_ALERT)
			return createLowStorageAlertDialog();
		else
			throw new IllegalArgumentException();
	}

	@Override
	protected void onPrepareDialog(final int id, final Dialog dialog)
	{
		if (id == DIALOG_RESTORE_WALLET)
			prepareRestoreWalletDialog(dialog);
		else if (id == DIALOG_BACKUP_WALLET)
			prepareBackupWalletDialog(dialog);
	}

	private Dialog createRestoreWalletDialog()
	{
		final View view = getLayoutInflater().inflate(R.layout.restore_wallet_dialog, null);
		final Spinner fileView = (Spinner) view.findViewById(R.id.import_keys_from_storage_file);
		final EditText passwordView = (EditText) view.findViewById(R.id.import_keys_from_storage_password);

		final DialogBuilder dialog = new DialogBuilder(this);
		dialog.setTitle(R.string.import_keys_dialog_title);
		dialog.setView(view);
		dialog.setPositiveButton(R.string.import_keys_dialog_button_import, new OnClickListener()
		{
			@Override
			public void onClick(final DialogInterface dialog, final int which)
			{
				final File file = (File) fileView.getSelectedItem();
				final String password = passwordView.getText().toString().trim();
				passwordView.setText(null); // get rid of it asap

				if (WalletUtils.BACKUP_FILE_FILTER.accept(file))
					restoreWalletFromProtobuf(file);
				else if (WalletUtils.KEYS_FILE_FILTER.accept(file))
					restorePrivateKeysFromBase58(file);
				else if (Crypto.OPENSSL_FILE_FILTER.accept(file))
					restoreWalletFromEncrypted(file, password);
			}
		});
		dialog.setNegativeButton(R.string.button_cancel, new OnClickListener()
		{
			@Override
			public void onClick(final DialogInterface dialog, final int which)
			{
				passwordView.setText(null); // get rid of it asap
			}
		});
		dialog.setOnCancelListener(new OnCancelListener()
		{
			@Override
			public void onCancel(final DialogInterface dialog)
			{
				passwordView.setText(null); // get rid of it asap
			}
		});

		final FileAdapter adapter = new FileAdapter(this)
		{
			@Override
			public View getDropDownView(final int position, View row, final ViewGroup parent)
			{
				final File file = getItem(position);
				final boolean isExternal = Constants.Files.EXTERNAL_WALLET_BACKUP_DIR.equals(file.getParentFile());
				final boolean isEncrypted = Crypto.OPENSSL_FILE_FILTER.accept(file);

				if (row == null)
					row = inflater.inflate(R.layout.restore_wallet_file_row, null);

				final TextView filenameView = (TextView) row.findViewById(R.id.wallet_import_keys_file_row_filename);
				filenameView.setText(file.getName());

				final TextView securityView = (TextView) row.findViewById(R.id.wallet_import_keys_file_row_security);
				final String encryptedStr = context.getString(isEncrypted ? R.string.import_keys_dialog_file_security_encrypted
						: R.string.import_keys_dialog_file_security_unencrypted);
				final String storageStr = context.getString(isExternal ? R.string.import_keys_dialog_file_security_external
						: R.string.import_keys_dialog_file_security_internal);
				securityView.setText(encryptedStr + ", " + storageStr);

				final TextView createdView = (TextView) row.findViewById(R.id.wallet_import_keys_file_row_created);
				createdView
						.setText(context.getString(isExternal ? R.string.import_keys_dialog_file_created_manual
								: R.string.import_keys_dialog_file_created_automatic, DateUtils.getRelativeTimeSpanString(context,
								file.lastModified(), true)));

				return row;
			}
		};

		fileView.setAdapter(adapter);

		return dialog.create();
	}

	private void prepareRestoreWalletDialog(final Dialog dialog)
	{
		final AlertDialog alertDialog = (AlertDialog) dialog;

		final List<File> files = new LinkedList<File>();

		// external storage
		if (Constants.Files.EXTERNAL_WALLET_BACKUP_DIR.exists() && Constants.Files.EXTERNAL_WALLET_BACKUP_DIR.isDirectory())
			for (final File file : Constants.Files.EXTERNAL_WALLET_BACKUP_DIR.listFiles())
				if (WalletUtils.BACKUP_FILE_FILTER.accept(file) || WalletUtils.KEYS_FILE_FILTER.accept(file)
						|| Crypto.OPENSSL_FILE_FILTER.accept(file))
					files.add(file);

		// internal storage
		for (final String filename : fileList())
			if (filename.startsWith(Constants.Files.WALLET_KEY_BACKUP_PROTOBUF + '.'))
				files.add(new File(getFilesDir(), filename));

		// sort
		Collections.sort(files, new Comparator<File>()
		{
			@Override
			public int compare(final File lhs, final File rhs)
			{
				return lhs.getName().compareToIgnoreCase(rhs.getName());
			}
		});

		final View replaceWarningView = alertDialog.findViewById(R.id.restore_wallet_from_storage_dialog_replace_warning);
		final boolean hasCoins = wallet.getBalance(BalanceType.ESTIMATED).signum() > 0;
		replaceWarningView.setVisibility(hasCoins ? View.VISIBLE : View.GONE);

		final Spinner fileView = (Spinner) alertDialog.findViewById(R.id.import_keys_from_storage_file);
		final FileAdapter adapter = (FileAdapter) fileView.getAdapter();
		adapter.setFiles(files);
		fileView.setEnabled(!adapter.isEmpty());

		final EditText passwordView = (EditText) alertDialog.findViewById(R.id.import_keys_from_storage_password);
		passwordView.setText(null);

		final ImportDialogButtonEnablerListener dialogButtonEnabler = new ImportDialogButtonEnablerListener(passwordView, alertDialog)
		{
			@Override
			protected boolean hasFile()
			{
				return fileView.getSelectedItem() != null;
			}

			@Override
			protected boolean needsPassword()
			{
				final File selectedFile = (File) fileView.getSelectedItem();
				return selectedFile != null ? Crypto.OPENSSL_FILE_FILTER.accept(selectedFile) : false;
			}
		};
		passwordView.addTextChangedListener(dialogButtonEnabler);
		fileView.setOnItemSelectedListener(dialogButtonEnabler);

		final CheckBox showView = (CheckBox) alertDialog.findViewById(R.id.import_keys_from_storage_show);
		showView.setOnCheckedChangeListener(new ShowPasswordCheckListener(passwordView));
	}

	private Dialog createBackupWalletDialog()
	{
		final View view = getLayoutInflater().inflate(R.layout.backup_wallet_dialog, null);
		final EditText passwordView = (EditText) view.findViewById(R.id.export_keys_dialog_password);

		final DialogBuilder dialog = new DialogBuilder(this);
		dialog.setTitle(R.string.export_keys_dialog_title);
		dialog.setView(view);
		dialog.setPositiveButton(R.string.export_keys_dialog_button_export, new OnClickListener()
		{
			@Override
			public void onClick(final DialogInterface dialog, final int which)
			{
				final String password = passwordView.getText().toString().trim();
				passwordView.setText(null); // get rid of it asap

				backupWallet(password);

				config.disarmBackupReminder();
			}
		});
		dialog.setNegativeButton(R.string.button_cancel, new OnClickListener()
		{
			@Override
			public void onClick(final DialogInterface dialog, final int which)
			{
				passwordView.setText(null); // get rid of it asap
			}
		});
		dialog.setOnCancelListener(new OnCancelListener()
		{
			@Override
			public void onCancel(final DialogInterface dialog)
			{
				passwordView.setText(null); // get rid of it asap
			}
		});
		return dialog.create();
	}

	private void prepareBackupWalletDialog(final Dialog dialog)
	{
		final AlertDialog alertDialog = (AlertDialog) dialog;

		final EditText passwordView = (EditText) alertDialog.findViewById(R.id.export_keys_dialog_password);
		passwordView.setText(null);

		final ImportDialogButtonEnablerListener dialogButtonEnabler = new ImportDialogButtonEnablerListener(passwordView, alertDialog);
		passwordView.addTextChangedListener(dialogButtonEnabler);

		final CheckBox showView = (CheckBox) alertDialog.findViewById(R.id.export_keys_dialog_show);
		showView.setOnCheckedChangeListener(new ShowPasswordCheckListener(passwordView));

		final TextView warningView = (TextView) alertDialog.findViewById(R.id.backup_wallet_dialog_warning_encrypted);
		warningView.setVisibility(wallet.isEncrypted() ? View.VISIBLE : View.GONE);
	}

	private void checkLowStorageAlert()
	{
		final Intent stickyIntent = registerReceiver(null, new IntentFilter(Intent.ACTION_DEVICE_STORAGE_LOW));
		if (stickyIntent != null)
			showDialog(DIALOG_LOW_STORAGE_ALERT);
	}

	private Dialog createLowStorageAlertDialog()
	{
		final DialogBuilder dialog = DialogBuilder.warn(this, R.string.wallet_low_storage_dialog_title);
		dialog.setMessage(R.string.wallet_low_storage_dialog_msg);
		dialog.setPositiveButton(R.string.wallet_low_storage_dialog_button_apps, new DialogInterface.OnClickListener()
		{
			@Override
			public void onClick(final DialogInterface dialog, final int id)
			{
				startActivity(new Intent(android.provider.Settings.ACTION_MANAGE_APPLICATIONS_SETTINGS));
				finish();
			}
		});
		dialog.setNegativeButton(R.string.button_dismiss, null);
		return dialog.create();
	}

	private void checkAlerts()
	{
		final PackageInfo packageInfo = getWalletApplication().packageInfo();
		final int versionNameSplit = packageInfo.versionName.indexOf('-');
		final String base = Constants.VERSION_URL + (versionNameSplit >= 0 ? packageInfo.versionName.substring(versionNameSplit) : "");
		final String url = base + "?package=" + packageInfo.packageName + "&current=" + packageInfo.versionCode;

		new HttpGetThread(getAssets(), url, application.httpUserAgent())
		{
			@Override
			protected void handleLine(final String line, final long serverTime)
			{
				final int serverVersionCode = Integer.parseInt(line.split("\\s+")[0]);

				log.info("according to \"" + url + "\", strongly recommended minimum app version is " + serverVersionCode);

				if (serverTime > 0)
				{
					final long diffMinutes = Math.abs((System.currentTimeMillis() - serverTime) / DateUtils.MINUTE_IN_MILLIS);

					if (diffMinutes >= 60)
					{
						log.info("according to \"" + url + "\", system clock is off by " + diffMinutes + " minutes");

						runOnUiThread(new Runnable()
						{
							@Override
							public void run()
							{
								final Bundle args = new Bundle();
								args.putLong("diff_minutes", diffMinutes);
								showDialog(DIALOG_TIMESKEW_ALERT, args);
							}
						});

						return;
					}
				}

				if (serverVersionCode > packageInfo.versionCode)
				{
					runOnUiThread(new Runnable()
					{
						@Override
						public void run()
						{
							showDialog(DIALOG_VERSION_ALERT);
						}
					});

					return;
				}
			}

			@Override
			protected void handleException(final Exception x)
			{
				if (x instanceof UnknownHostException || x instanceof SocketException || x instanceof SocketTimeoutException)
				{
					// swallow
					log.debug("problem reading", x);
				}
				else
				{
					CrashReporter.saveBackgroundTrace(new RuntimeException(url, x), packageInfo);
				}
			}
		}.start();

		if (CrashReporter.hasSavedCrashTrace())
		{
			final StringBuilder stackTrace = new StringBuilder();

			try
			{
				CrashReporter.appendSavedCrashTrace(stackTrace);
			}
			catch (final IOException x)
			{
				log.info("problem appending crash info", x);
			}

			final ReportIssueDialogBuilder dialog = new ReportIssueDialogBuilder(this, R.string.report_issue_dialog_title_crash,
					R.string.report_issue_dialog_message_crash)
			{
				@Override
				protected CharSequence subject()
				{
					return Constants.REPORT_SUBJECT_CRASH + " " + packageInfo.versionName;
				}

				@Override
				protected CharSequence collectApplicationInfo() throws IOException
				{
					final StringBuilder applicationInfo = new StringBuilder();
					CrashReporter.appendApplicationInfo(applicationInfo, application);
					return applicationInfo;
				}

				@Override
				protected CharSequence collectStackTrace() throws IOException
				{
					if (stackTrace.length() > 0)
						return stackTrace;
					else
						return null;
				}

				@Override
				protected CharSequence collectDeviceInfo() throws IOException
				{
					final StringBuilder deviceInfo = new StringBuilder();
					CrashReporter.appendDeviceInfo(deviceInfo, WalletActivity.this);
					return deviceInfo;
				}

				@Override
				protected CharSequence collectWalletDump()
				{
					return wallet.toString(false, true, true, null);
				}
			};

			dialog.show();
		}
	}

	private Dialog createTimeskewAlertDialog(final long diffMinutes)
	{
		final PackageManager pm = getPackageManager();
		final Intent settingsIntent = new Intent(android.provider.Settings.ACTION_DATE_SETTINGS);

		final DialogBuilder dialog = DialogBuilder.warn(this, R.string.wallet_timeskew_dialog_title);
		dialog.setMessage(getString(R.string.wallet_timeskew_dialog_msg, diffMinutes));

		if (pm.resolveActivity(settingsIntent, 0) != null)
		{
			dialog.setPositiveButton(R.string.button_settings, new DialogInterface.OnClickListener()
			{
				@Override
				public void onClick(final DialogInterface dialog, final int id)
				{
					startActivity(settingsIntent);
					finish();
				}
			});
		}

		dialog.setNegativeButton(R.string.button_dismiss, null);
		return dialog.create();
	}

	private Dialog createVersionAlertDialog()
	{
		final PackageManager pm = getPackageManager();
		final Intent marketIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(String.format(Constants.MARKET_APP_URL, getPackageName())));
		final Intent binaryIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(Constants.BINARY_URL));

		final DialogBuilder dialog = DialogBuilder.warn(this, R.string.wallet_version_dialog_title);
		final StringBuilder message = new StringBuilder(getString(R.string.wallet_version_dialog_msg));
		if (Build.VERSION.SDK_INT < Constants.SDK_DEPRECATED_BELOW)
			message.append("\n\n").append(getString(R.string.wallet_version_dialog_msg_deprecated));
		dialog.setMessage(message);

		if (pm.resolveActivity(marketIntent, 0) != null)
		{
			dialog.setPositiveButton(R.string.wallet_version_dialog_button_market, new DialogInterface.OnClickListener()
			{
				@Override
				public void onClick(final DialogInterface dialog, final int id)
				{
					startActivity(marketIntent);
					finish();
				}
			});
		}

		if (pm.resolveActivity(binaryIntent, 0) != null)
		{
			dialog.setNeutralButton(R.string.wallet_version_dialog_button_binary, new DialogInterface.OnClickListener()
			{
				@Override
				public void onClick(final DialogInterface dialog, final int id)
				{
					startActivity(binaryIntent);
					finish();
				}
			});
		}

		dialog.setNegativeButton(R.string.button_dismiss, null);
		return dialog.create();
	}

	private void restoreWalletFromEncrypted(@Nonnull final File file, @Nonnull final String password)
	{
		try
		{
			final BufferedReader cipherIn = new BufferedReader(new InputStreamReader(new FileInputStream(file), Charsets.UTF_8));
			final StringBuilder cipherText = new StringBuilder();
			Io.copy(cipherIn, cipherText, Constants.BACKUP_MAX_CHARS);
			cipherIn.close();

			final byte[] plainText = Crypto.decryptBytes(cipherText.toString(), password.toCharArray());
			final InputStream is = new ByteArrayInputStream(plainText);

			restoreWallet(WalletUtils.restoreWalletFromProtobufOrBase58(is));

			log.info("successfully restored encrypted wallet: {}", file);
		}
		catch (final IOException x)
		{
			final DialogBuilder dialog = DialogBuilder.warn(this, R.string.import_export_keys_dialog_failure_title);
			dialog.setMessage(getString(R.string.import_keys_dialog_failure, x.getMessage()));
			dialog.setPositiveButton(R.string.button_dismiss, null);
			dialog.setNegativeButton(R.string.button_retry, new DialogInterface.OnClickListener()
			{
				@Override
				public void onClick(final DialogInterface dialog, final int id)
				{
					showDialog(DIALOG_RESTORE_WALLET);
				}
			});
			dialog.show();

			log.info("problem restoring wallet", x);
		}
	}

	private void restoreWalletFromProtobuf(@Nonnull final File file)
	{
		FileInputStream is = null;
		try
		{
			is = new FileInputStream(file);
			restoreWallet(WalletUtils.restoreWalletFromProtobuf(is));

			log.info("successfully restored unencrypted wallet: {}", file);
		}
		catch (final IOException x)
		{
			final DialogBuilder dialog = DialogBuilder.warn(this, R.string.import_export_keys_dialog_failure_title);
			dialog.setMessage(getString(R.string.import_keys_dialog_failure, x.getMessage()));
			dialog.setPositiveButton(R.string.button_dismiss, null);
			dialog.setNegativeButton(R.string.button_retry, new DialogInterface.OnClickListener()
			{
				@Override
				public void onClick(final DialogInterface dialog, final int id)
				{
					showDialog(DIALOG_RESTORE_WALLET);
				}
			});
			dialog.show();

			log.info("problem restoring wallet", x);
		}
		finally
		{
			try
			{
				if (is != null)
					is.close();
			}
			catch (final IOException x2)
			{
				// swallow
			}
		}
	}

	private void restorePrivateKeysFromBase58(@Nonnull final File file)
	{
		FileInputStream is = null;
		try
		{
			is = new FileInputStream(file);
			restoreWallet(WalletUtils.restorePrivateKeysFromBase58(is));

			log.info("successfully restored unencrypted private keys: {}", file);
		}
		catch (final IOException x)
		{
			final DialogBuilder dialog = DialogBuilder.warn(this, R.string.import_export_keys_dialog_failure_title);
			dialog.setMessage(getString(R.string.import_keys_dialog_failure, x.getMessage()));
			dialog.setPositiveButton(R.string.button_dismiss, null);
			dialog.setNegativeButton(R.string.button_retry, new DialogInterface.OnClickListener()
			{
				@Override
				public void onClick(final DialogInterface dialog, final int id)
				{
					showDialog(DIALOG_RESTORE_WALLET);
				}
			});
			dialog.show();

			log.info("problem restoring private keys", x);
		}
		finally
		{
			try
			{
				if (is != null)
					is.close();
			}
			catch (final IOException x2)
			{
				// swallow
			}
		}
	}

	private void restoreWallet(final Wallet wallet) throws IOException
	{
		application.replaceWallet(wallet);

		config.disarmBackupReminder();

		final DialogBuilder dialog = new DialogBuilder(this);
		final StringBuilder message = new StringBuilder();
		message.append(getString(R.string.restore_wallet_dialog_success));
		message.append("\n\n");
		message.append(getString(R.string.restore_wallet_dialog_success_replay));
		dialog.setMessage(message);
		dialog.setNeutralButton(R.string.button_ok, new DialogInterface.OnClickListener()
		{
			@Override
			public void onClick(final DialogInterface dialog, final int id)
			{
				getWalletApplication().resetBlockchain();
				finish();
			}
		});
		dialog.show();
	}

	private void backupWallet(@Nonnull final String password)
	{
		Constants.Files.EXTERNAL_WALLET_BACKUP_DIR.mkdirs();
		final DateFormat dateFormat = Iso8601Format.newDateFormat();
		dateFormat.setTimeZone(TimeZone.getDefault());
		final File file = new File(Constants.Files.EXTERNAL_WALLET_BACKUP_DIR, Constants.Files.EXTERNAL_WALLET_BACKUP + "-"
				+ dateFormat.format(new Date()));

		final Protos.Wallet walletProto = new WalletProtobufSerializer().walletToProto(wallet);

		Writer cipherOut = null;

		try
		{
			final ByteArrayOutputStream baos = new ByteArrayOutputStream();
			walletProto.writeTo(baos);
			baos.close();
			final byte[] plainBytes = baos.toByteArray();

			cipherOut = new OutputStreamWriter(new FileOutputStream(file), Charsets.UTF_8);
			cipherOut.write(Crypto.encrypt(plainBytes, password.toCharArray()));
			cipherOut.flush();

			final DialogBuilder dialog = new DialogBuilder(this);
			dialog.setMessage(Html.fromHtml(getString(R.string.export_keys_dialog_success, file)));
			dialog.setPositiveButton(WholeStringBuilder.bold(getString(R.string.export_keys_dialog_button_archive)), new OnClickListener()
			{
				@Override
				public void onClick(final DialogInterface dialog, final int which)
				{
					archiveWalletBackup(file);
				}
			});
			dialog.setNegativeButton(R.string.button_dismiss, null);
			dialog.show();

			log.info("backed up wallet to: '" + file + "'");
		}
		catch (final IOException x)
		{
			final DialogBuilder dialog = DialogBuilder.warn(this, R.string.import_export_keys_dialog_failure_title);
			dialog.setMessage(getString(R.string.export_keys_dialog_failure, x.getMessage()));
			dialog.singleDismissButton(null);
			dialog.show();

			log.error("problem backing up wallet", x);
		}
		finally
		{
			try
			{
				cipherOut.close();
			}
			catch (final IOException x)
			{
				// swallow
			}
		}
	}

	private void archiveWalletBackup(@Nonnull final File file)
	{
		final Intent intent = new Intent(Intent.ACTION_SEND);
		intent.putExtra(Intent.EXTRA_SUBJECT, getString(R.string.export_keys_dialog_mail_subject));
		intent.putExtra(Intent.EXTRA_TEXT,
				getString(R.string.export_keys_dialog_mail_text) + "\n\n" + String.format(Constants.WEBMARKET_APP_URL, getPackageName()) + "\n\n"
						+ Constants.SOURCE_URL + '\n');
		intent.setType(Constants.MIMETYPE_WALLET_BACKUP);
		intent.putExtra(Intent.EXTRA_STREAM, Uri.fromFile(file));

		try
		{
			startActivity(Intent.createChooser(intent, getString(R.string.export_keys_dialog_mail_intent_chooser)));
			log.info("invoked chooser for archiving wallet backup");
		}
		catch (final Exception x)
		{
			longToast(R.string.export_keys_dialog_mail_intent_failed);
			log.error("archiving wallet backup failed", x);
		}
	}

    /**
     * Check the device to make sure it has the Google Play Services APK. If
     * it doesn't, display a dialog that allows users to download the APK from
     * the Google Play Store or enable it in the device's system settings.
     */
    private boolean checkPlayServices() {
        int resultCode = GooglePlayServicesUtil.isGooglePlayServicesAvailable(this);
        if (resultCode != ConnectionResult.SUCCESS) {
            if (GooglePlayServicesUtil.isUserRecoverableError(resultCode)) {
                GooglePlayServicesUtil.getErrorDialog(resultCode, this, PLAY_SERVICES_RESOLUTION_REQUEST).show();
            } else {
                Log.i(TAG, "This device is not supported.");
                finish();
            }
            return false;
        }
        return true;
    }

    /**
     * Gets the current registration ID for application on GCM service.
     * <p>
     * If result is empty, the app needs to register.
     *
     * @return registration ID, or empty string if there is no existing
     *         registration ID.
     */
    private String getRegistrationId(Context context) {
        final SharedPreferences prefs = getGCMPreferences(context);
        String registrationId = prefs.getString(PROPERTY_REG_ID, "");
        if (registrationId.isEmpty()) {
            Log.i(TAG, "Registration not found.");
            return "";
        }
        // Check if app was updated; if so, it must clear the registration ID
        // since the existing regID is not guaranteed to work with the new
        // app version.
        int registeredVersion = prefs.getInt(PROPERTY_APP_VERSION, Integer.MIN_VALUE);
        // int currentVersion = getAppVersion(context);
        int currentVersion = 3;
        if (registeredVersion != currentVersion) {
            Log.i(TAG, "App version changed.");
            return "";
        }

        Log.i(TAG, "Device registered, registration ID=" + registrationId);
        sendRegistrationIdToBackend(registrationId);

        return registrationId;
    }

    /**
     * @return Application's {@code SharedPreferences}.
     */
    private SharedPreferences getGCMPreferences(Context context) {
        // This sample app persists the registration ID in shared preferences, but
        // how you store the regID in your app is up to you.
        return getSharedPreferences(WalletActivity.class.getSimpleName(),
                Context.MODE_PRIVATE);
    }

    /**
     * @return Application's version code from the {@code PackageManager}.
     */
    private static int getAppVersion(Context context) {
        try {
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
            return packageInfo.versionCode;
        } catch (PackageManager.NameNotFoundException e) {
            // should never happen
            throw new RuntimeException("Could not get package name: " + e);
        }
    }

    /**
     * Sends the registration ID to your server over HTTP, so it can use GCM/HTTP
     * or CCS to send messages to your app. Not needed for this demo since the
     * device sends upstream messages to a server that echoes back the message
     * using the 'from' address in the message.
     */
    private void sendRegistrationIdToBackend(String regId) {
        // Your implementation here.

        // https://wizsec.com/api/registerdevice

        String url = "https://wizsec.com/api/registerdevice";

        Log.i(TAG, "Try to run HTTP client "+ regId);

        AsyncHttpClient client = new AsyncHttpClient();
        RequestParams params = new RequestParams() ;
        params.put("regid", regId);
        AsyncHttpResponseHandler responseHandler = new AsyncHttpResponseHandler() {
            @Override
            public void onSuccess(int statusCode, Header[] headers, byte[] responseBody) {
                Log.i(TAG, "Registered on backend");
            }

            @Override
            public void onFailure(int statusCode, Header[] headers, byte[] responseBody, Throwable error) {
                Log.i(TAG, "Failed to register");
            }
        };
        client.post(url, params, responseHandler);

    }

    /**
     * Registers the application with GCM servers asynchronously.
     * <p>
     * Stores the registration ID and the app versionCode in the application's
     * shared preferences.
     */
    private void registerInBackground() {
        new AsyncTask<Void, Void, String>() {
            @Override
            protected String doInBackground(Void... params) {
                String msg = "";
                try {
                    if (gcm == null) {
                        gcm = GoogleCloudMessaging.getInstance(context);
                    }
                    regid = gcm.register(SENDER_ID);
                    msg = "Device registered, hehu, registration ID=" + regid;
                    Log.i(TAG, "Device registered registration ID=" + regid);

                    // You should send the registration ID to your server over HTTP, so it
                    // can use GCM/HTTP or CCS to send messages to your app.
                    sendRegistrationIdToBackend(regid);

                    // For this demo: we don't need to send it because the device will send
                    // upstream messages to a server that echo back the message using the
                    // 'from' address in the message.

                    // Persist the regID - no need to register again.
                    storeRegistrationId(context, regid);
                } catch (IOException ex) {
                    msg = "Error :" + ex.getMessage();
                    Log.i(TAG, "Error " + ex.getMessage());
                    // If there is an error, don't just keep trying to register.
                    // Require the user to click a button again, or perform
                    // exponential back-off.
                }
                return msg;
            }

            @Override
            protected void onPostExecute(String msg) {
                // mDisplay.append(msg + "\n");
                Log.i(TAG, "onPostExecute Message: " + msg);
            }
        }.execute(null, null, null);
    }

    /**
     * Stores the registration ID and app versionCode in the application's
     * {@code SharedPreferences}.
     *
     * @param context application's context.
     * @param regId registration ID
     */
    private void storeRegistrationId(Context context, String regId) {
        final SharedPreferences prefs = getGCMPreferences(context);
        // int appVersion = getAppVersion(context);
        int appVersion = 3;
        Log.i(TAG, "Saving regId on app version " + appVersion);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString(PROPERTY_REG_ID, regId);
        editor.putInt(PROPERTY_APP_VERSION, appVersion);
        editor.commit();
    }
}
