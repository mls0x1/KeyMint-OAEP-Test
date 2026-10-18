package dev.oaep.probe;

import android.app.Activity;
import android.os.Bundle;
import android.graphics.Color;
import android.graphics.Insets;
import android.view.WindowInsets;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.view.Gravity;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public final class MainActivity extends Activity {
    private static final String TAG = "KM_OAEP";
    private TextView output;
    private Button button;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        // Android 15+ edge-to-edge: keep controls clear of system bars.
        int pad = (int) (18 * getResources().getDisplayMetrics().density);

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setClipToPadding(false);
        scroll.setBackgroundColor(Color.WHITE);
        scroll.setOnApplyWindowInsetsListener((view, insets) -> {
            Insets bars = insets.getInsets(WindowInsets.Type.systemBars());
            view.setPadding(pad, pad + bars.top, pad, pad + bars.bottom);
            return insets;
        });

        LinearLayout column = new LinearLayout(this);
        column.setOrientation(LinearLayout.VERTICAL);
        column.setFocusableInTouchMode(true);

        TextView title = new TextView(this);
        title.setText("KeyMint RSA-OAEP testi");
        title.setTextColor(Color.BLACK);
        title.setTextSize(23);
        title.setPadding(0, 0, 0, pad);

        button = new Button(this);
        button.setText("RSA-OAEP MGF1 TESTİNİ ÇALIŞTIR");
        button.setAllCaps(false);

        TextView intro = new TextView(this);
        intro.setText("AndroidKeyStore üzerinde MGF1 SHA-1 ve SHA-256 karşılaştırılır. Test anahtarı yalnızca bu uygulama için oluşturulur ve silinir.");
        intro.setTextColor(Color.DKGRAY);
        intro.setTextSize(14);
        intro.setPadding(0, pad / 2, 0, pad);

        output = new TextView(this);
        output.setTextSize(14);
        output.setTextColor(Color.BLACK);
        output.setText("Hazır. Yukarıdaki test düğmesine bas.\n");

        column.addView(title);
        column.addView(button);
        column.addView(intro);
        column.addView(output);
        scroll.addView(column);
        setContentView(scroll);
        column.requestFocus();
        scroll.requestApplyInsets();
        button.setOnClickListener(v -> {
            button.setEnabled(false);
            output.setText("Test başlıyor…\n");
            new Thread(this::runTest, "oaep-test").start();
        });
    }

    private void emit(String s) {
        Log.i(TAG, s);
        runOnUiThread(() -> output.append(s + "\n"));
    }

    private static String message(Throwable t) {
        StringBuilder text = new StringBuilder();
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (text.length() > 0) text.append(" <- ");
            text.append(c.getClass().getSimpleName()).append(": ").append(c.getMessage());
        }
        return text.toString();
    }

    private void runTest() {
        String alias = "probe_" + System.currentTimeMillis();
        KeyStore store = null;
        try {
            store = KeyStore.getInstance("AndroidKeyStore");
            store.load(null);
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(2048)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    .setMgf1Digests(KeyProperties.DIGEST_SHA1, KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(false)
                    .build();
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
            generator.initialize(spec);
            emit("Anahtar oluşturuluyor…");
            KeyPair pair = generator.generateKeyPair();
            emit("Anahtar üretimi: PASS");
            try {
                KeyFactory androidKeyFactory = KeyFactory.getInstance("RSA", "AndroidKeyStore");
                KeyInfo info = androidKeyFactory.getKeySpec(pair.getPrivate(), KeyInfo.class);
                emit("Key security level: " + info.getSecurityLevel() + " (0=Software, 1=TEE, 2=StrongBox)");
            } catch (Exception e) { emit("KeyInfo sorgusu: " + message(e)); }

            PublicKey softwarePublicKey = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(pair.getPublic().getEncoded()));
            byte[] plain = "Android KeyMint OAEP test".getBytes(StandardCharsets.UTF_8);
            for (String mgfDigest : new String[] {"SHA-1", "SHA-256"}) {
                try {
                    OAEPParameterSpec oaep = new OAEPParameterSpec(
                            "SHA-256", "MGF1", new MGF1ParameterSpec(mgfDigest),
                            PSource.PSpecified.DEFAULT);
                    Cipher encrypt = Cipher.getInstance("RSA/ECB/OAEPPadding");
                    encrypt.init(Cipher.ENCRYPT_MODE, softwarePublicKey, oaep);
                    byte[] ciphertext = encrypt.doFinal(plain);
                    Cipher decrypt = Cipher.getInstance("RSA/ECB/OAEPPadding");
                    decrypt.init(Cipher.DECRYPT_MODE, pair.getPrivate(), oaep);
                    byte[] decrypted = decrypt.doFinal(ciphertext);
                    emit("MGF1=" + mgfDigest + " result=" +
                            (Arrays.equals(plain, decrypted) ? "PASS" : "FAIL (plaintext mismatch)") +
                            " encProvider=" + encrypt.getProvider().getName() +
                            " decProvider=" + decrypt.getProvider().getName());
                } catch (Exception e) {
                    emit("MGF1=" + mgfDigest + " FAILED: " + message(e));
                }
            }
        } catch (Exception e) {
            emit("KEYGEN FAILED: " + message(e));
        } finally {
            if (store != null) {
                try { store.deleteEntry(alias); emit("Geçici anahtar silindi."); }
                catch (Exception e) { emit("Anahtar temizleme hatası: " + message(e)); }
            }
            runOnUiThread(() -> button.setEnabled(true));
        }
    }
}
