# KeyMint OAEP Test (Android Studio gerektirmez)

Android 15+ / API 35+ cihazlarda AndroidKeyStore RSA-OAEP SHA-256 decryption testi. MGF1 SHA-1 ve SHA-256 varyantları denenir. Yalnızca geçici, uygulamaya ait anahtar oluşturur; ardından onu siler. Root veya internet istemez. Play Integrity değiştirmez.

## GitHub Actions üzerinden APK oluşturma
1. GitHub'da yeni, tercihen **private** bir repo açın.
2. Bu ZIP'in **içeriğini** (ZIP dosyasının kendisini değil) repo köküne yükleyin. `.github/workflows/build.yml` gizli klasör olduğu için de yüklenmelidir.
3. **Actions** sekmesinde **Build test APK** iş akışını çalıştırın (veya `main` branch'e commit yapın).
4. Başarılı tamamlanınca iş akışının **Artifacts** kısmından `KeyMintOAEP-Test-APK` indirin. İçindeki `app-debug.apk` test APK'sıdır.
5. Telefona kurun: `adb install -r app-debug.apk`
6. Uygulamayı açıp butona basın; ekranda `MGF1=SHA-1` ve `MGF1=SHA-256` sonuçlarını karşılaştırın.

Komutla izleme: `adb logcat -s KM_OAEP:I '*:S'`

**Uyarı:** Kaynak dosyalar proje olarak hazırlanmıştır; bu ortamda Android SDK olmadığı için burada APK derlenip gerçek cihazda doğrulanmadı. Build hatası olursa Actions logunu paylaşın. Test sonuçları yalnızca ilgili JCA/KeyMint kombinasyonunda uyumluluğu ölçer. Modülleri karşılaştırırken cihazda hangi modüllerin etkin olduğunu not edin.
