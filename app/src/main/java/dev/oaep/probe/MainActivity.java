package dev.oaep.probe;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Insets;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.security.auth.x500.X500Principal;

/**
 * KeyMint RSA-OAEP comparison test.
 *
 * Duck Detector 2026.10.02 implementation reference:
 * eltavine/Duck-Detector-Refactoring,
 * KeyMintCryptoChecks.kt rsaOaepSha256RoundTrip and KeyMintCryptoSupport.kt.
 *
 * The Duck-identical test requests an attestation certificate once. The other
 * cases do not request remote provisioning. No existing keys are modified.
 */
public final class MainActivity extends Activity {
    private static final String TAG = "KM_OAEP";
    private static final String GENERIC_TRANSFORM = "RSA/ECB/OAEPPadding";
    private static final String DUCK_TRANSFORM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private TextView output;
    private Button button;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
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
        title.setText("KeyMint RSA-OAEP karşılaştırması v1.2");
        title.setTextColor(Color.BLACK);
        title.setTextSize(22);
        title.setPadding(0, 0, 0, pad);

        button = new Button(this);
        button.setText("4 KARŞILAŞTIRMA TESTİNİ ÇALIŞTIR");
        button.setAllCaps(false);

        TextView intro = new TextView(this);
        intro.setText("A: Önceki başarılı test (SHA-1 ve SHA-256). " +
                "B: Duck algoritması, MGF1 belirtilmemiş. " +
                "C: Aynı test, MGF1 SHA-1 açıkça izinli. " +
                "D: Duck Detector'ın anahtar/attestation ayarlarıyla tam test.\n" +
                "D, yalnızca bir kez sertifika talep eder; RKP tetiklenebilir. " +
                "Yeni geçici anahtarlar test sonunda silinir.");
        intro.setTextColor(Color.DKGRAY);
        intro.setTextSize(14);
        intro.setPadding(0, pad / 2, 0, pad);

        output = new TextView(this);
        output.setTextSize(14);
        output.setTextColor(Color.BLACK);
        output.setTextIsSelectable(true);
        output.setText("Hazır. Sonuçları uzun basarak seçip kopyalayabilirsin.\n");

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
            new Thread(this::runAll, "oaep-test").start();
        });
    }

    private void emit(String text) {
        Log.i(TAG, text);
        runOnUiThread(() -> output.append(text + "\n"));
    }

    private static String explain(Throwable throwable) {
        StringBuilder result = new StringBuilder();
        int depth = 0;
        for (Throwable c = throwable; c != null && depth < 8; c = c.getCause(), depth++) {
            if (result.length() > 0) result.append(" <- ");
            result.append(c.getClass().getName());
            if (c.getMessage() != null) result.append(": ").append(c.getMessage());
            if (c.getCause() == c) break;
        }
        return result.toString();
    }

    private static final class CaseSpec {
        final String id;
        final String title;
        final boolean duckTransform;
        final boolean duckCertificateInfo;
        final boolean challenge;
        final int mgfPermissions; // 0=unspecified, 1=SHA-1, 2=SHA-1+SHA-256

        CaseSpec(String id, String title, boolean duckTransform,
                 boolean duckCertificateInfo, boolean challenge, int mgfPermissions) {
            this.id = id;
            this.title = title;
            this.duckTransform = duckTransform;
            this.duckCertificateInfo = duckCertificateInfo;
            this.challenge = challenge;
            this.mgfPermissions = mgfPermissions;
        }
    }

    private void runAll() {
        try {
            emit("Android " + android.os.Build.VERSION.RELEASE + " (SDK " +
                    android.os.Build.VERSION.SDK_INT + ")");
            emit("D testi attestation/RKP isteği oluşturabilir; yalnızca bir kez çalışır.");

            runCase(new CaseSpec("A", "Eski referans, MGF1 SHA-1 + SHA-256", false, false, false, 2));
            runCase(new CaseSpec("B", "Duck crypto, MGF1 belirtilmemiş, challenge yok",
                    true, true, false, 0));
            runCase(new CaseSpec("C", "Duck crypto, MGF1 SHA-1 izinli, challenge yok",
                    true, true, false, 1));
            runCase(new CaseSpec("D", "Duck birebir, attestation challenge var",
                    true, true, true, 0));

            emit("\nBitti. A/B/C/D sonuçlarını ve hata zincirlerini paylaş.");
        } catch (Throwable throwable) {
            emit("Beklenmeyen test hatası: " + explain(throwable));
        } finally {
            runOnUiThread(() -> button.setEnabled(true));
        }
    }

    private void runCase(CaseSpec test) {
        final String alias = "oaep_diag_" + test.id.toLowerCase() + "_" + System.nanoTime();
        KeyStore store = null;
        String stage = "AndroidKeyStore load";
        try {
            emit("\n=== " + test.id + " — " + test.title + " ===");
            store = KeyStore.getInstance("AndroidKeyStore");
            store.load(null);

            stage = "build key spec";
            KeyGenParameterSpec.Builder builder =
                    new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_DECRYPT)
                            .setKeySize(2048)
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP);

            if (test.mgfPermissions == 1) {
                builder.setMgf1Digests(KeyProperties.DIGEST_SHA1);
            } else if (test.mgfPermissions == 2) {
                builder.setMgf1Digests(
                        KeyProperties.DIGEST_SHA1, KeyProperties.DIGEST_SHA256);
            }

            if (test.duckCertificateInfo) {
                Calendar now = Calendar.getInstance();
                Calendar later = Calendar.getInstance();
                later.add(Calendar.YEAR, 1);
                builder.setCertificateSubject(
                                new X500Principal("CN=DuckDetector KeyMint Probe, O=Eltavine"))
                        .setCertificateSerialNumber(BigInteger.valueOf(System.nanoTime()))
                        .setCertificateNotBefore(now.getTime())
                        .setCertificateNotAfter(later.getTime());
            }
            if (test.challenge) {
                builder.setAttestationChallenge("duck_keymint_probe".getBytes(StandardCharsets.UTF_8));
            }

            stage = "generateKeyPair";
            KeyPairGenerator generator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            generator.initialize(builder.build());
            KeyPair pair = generator.generateKeyPair();
            emit("Key generation: PASS; generator=" + generator.getProvider().getName());

            try {
                KeyInfo info = KeyFactory.getInstance("RSA", "AndroidKeyStore")
                        .getKeySpec(pair.getPrivate(), KeyInfo.class);
                emit("KeyInfo.securityLevel=" + info.getSecurityLevel() +
                        " (1=TEE, 2=StrongBox)");
            } catch (Exception e) {
                emit("KeyInfo: " + explain(e));
            }

            stage = "rebuild software public key";
            PublicKey softwareKey = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(pair.getPublic().getEncoded()));

            String transform = test.duckTransform ? DUCK_TRANSFORM : GENERIC_TRANSFORM;
            byte[] payload = (test.duckTransform ? "duck_oaep_sha256" :
                    "Android KeyMint OAEP test").getBytes(StandardCharsets.UTF_8);

            String[] digests = test.duckTransform ? new String[]{"SHA-1"} :
                    new String[]{"SHA-1", "SHA-256"};
            for (String mgf : digests) {
                OAEPParameterSpec params = new OAEPParameterSpec(
                        "SHA-256", "MGF1", new MGF1ParameterSpec(mgf),
                        PSource.PSpecified.DEFAULT);
                stage = "encrypt init (" + mgf + ")";
                Cipher cipherEncrypt = Cipher.getInstance(transform);
                cipherEncrypt.init(Cipher.ENCRYPT_MODE, softwareKey, params);
                stage = "encrypt doFinal (" + mgf + ")";
                byte[] encrypted = cipherEncrypt.doFinal(payload);
                emit("Encrypt: PASS; provider=" + cipherEncrypt.getProvider().getName() +
                        "; ciphertextBytes=" + encrypted.length);
                stage = "decrypt init (" + mgf + ")";
                Cipher cipherDecrypt = Cipher.getInstance(transform);
                cipherDecrypt.init(Cipher.DECRYPT_MODE, pair.getPrivate(), params);
                stage = "decrypt doFinal (" + mgf + ")";
                byte[] decrypted = cipherDecrypt.doFinal(encrypted);
                boolean matched = Arrays.equals(payload, decrypted);
                emit("MGF1 " + mgf + " result=" + (matched ? "PASS" : "FAIL: mismatch") +
                        "; decryptProvider=" + cipherDecrypt.getProvider().getName() +
                        "; decryptedBytes=" + decrypted.length);
            }
        } catch (Throwable error) {
            emit("TEST " + test.id + " FAIL at [" + stage + "]: " + explain(error));
        } finally {
            if (store != null) {
                try {
                    store.deleteEntry(alias);
                    emit("Temporary alias deleted.");
                } catch (Exception error) {
                    emit("Key cleanup ERROR: " + explain(error));
                }
            }
        }
    }
}
