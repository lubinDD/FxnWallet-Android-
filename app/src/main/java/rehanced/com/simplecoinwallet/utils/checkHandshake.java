package rehanced.com.simplecoinwallet.utils;

import android.util.Log;

import java.io.IOException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import okhttp3.CertificatePinner;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.Response;

/**
 * Created by dotFu on 9/18/2017.
 */

public class checkHandshake {

    private static final String TAG = checkHandshake.class.getSimpleName();

    /** Rejects otherwise-trusted certificates. */
    private static final Interceptor CHECK_HANDSHAKE_INTERCEPTOR = new Interceptor() {

        Set<String> blacklist = Collections.singleton(
                "sha256/afwiKY3RxoMmLkuRW1l7QsPZTJPwDS2pdDROQjXw8ig="
        );

        @Override
        public Response intercept(Chain chain) throws IOException {
            for (Certificate certificate : chain.connection().handshake().peerCertificates()) {
                String pin = CertificatePinner.pin(certificate);
                Log.e(TAG, "interceptPin: " + pin + " ");
                if (blacklist.contains(pin)) {
                    throw new IOException("Blacklisted peer certificate: " + pin);
                }
            }
            return chain.proceed(chain.request());
        }
    };

    private static OkHttpClient getUnsafeOkHttpClient() {
        try {
            // Create a trust manager that does not validate certificate chains
            final TrustManager[] trustAllCerts = new TrustManager[] {
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
                        }

                        @Override
                        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
                        }

                        @Override
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return new java.security.cert.X509Certificate[]{};
                        }
                    }
            };

            // Install the all-trusting trust manager
            final SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            // Create an ssl socket factory with our all-trusting manager
            final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            OkHttpClient.Builder builder = new OkHttpClient.Builder()
                    .connectTimeout(10, TimeUnit.SECONDS)
                    .writeTimeout(10, TimeUnit.SECONDS)
                    .readTimeout(10, TimeUnit.SECONDS);
            builder.sslSocketFactory(sslSocketFactory);
            builder.hostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            });
            //builder.addNetworkInterceptor(CHECK_HANDSHAKE_INTERCEPTOR);

            OkHttpClient okHttpClient = builder.build();
            return okHttpClient;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private final OkHttpClient client = getUnsafeOkHttpClient();

    public OkHttpClient getClient() {
        return client;
    }

}
