package rocks.inspectit.ocelot.core.exporter;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import io.opencensus.exporter.stats.prometheus.PrometheusStatsCollector;
import io.opencensus.exporter.stats.prometheus.PrometheusStatsConfiguration;
import io.prometheus.client.exporter.HTTPServer;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.stereotype.Component;
import rocks.inspectit.ocelot.config.model.InspectitConfig;
import rocks.inspectit.ocelot.core.service.DynamicallyActivatableService;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

import static io.prometheus.client.CollectorRegistry.defaultRegistry;

/**
 * Service for the Prometheus OpenCensus exporter.
 * Can be dynamically started and stopped using the exporters.metrics.prometheus.enabled configuration.
 */
@Component
@Slf4j
public class PrometheusExporterService extends DynamicallyActivatableService {

    private HTTPServer prometheusClient = null;

    public PrometheusExporterService() {
        super("exporters.metrics.prometheus", "metrics.enabled");
    }

    @Override
    protected boolean checkEnabledForConfig(InspectitConfig conf) {
        return conf.getExporters().getMetrics().getPrometheus().isEnabled() && conf.getMetrics().isEnabled();
    }

    @Override
    protected boolean doEnable(InspectitConfig configuration) {
        val config = configuration.getExporters().getMetrics().getPrometheus();
        try {
            String host = config.getHost();
            int port = config.getPort();
            log.info("Starting Prometheus Exporter on {}://{}:{}", getEndpointScheme(config.isTlsEnabled()), host, port);
            PrometheusStatsCollector.createAndRegister(PrometheusStatsConfiguration.builder().setRegistry(defaultRegistry).build());

            HTTPServer.Builder prometheusClientBuilder = new HTTPServer.Builder()
                    .withHostname(host)
                    .withPort(port)
                    .withDaemonThreads(true);

            if (config.isTlsEnabled()) {
                HttpsConfigurator  httpsConfigurator = createHttpsConfigurator(config.getKeyStoreType(), config.getKeyStoreFile(), config.getKeyStorePassword());
                prometheusClientBuilder.withHttpsConfigurator(httpsConfigurator);
            }

            prometheusClient = prometheusClientBuilder.build();
        } catch (Exception e) {
            log.error("Error Starting Prometheus HTTP Endpoint!", e);
            defaultRegistry.clear();
            return false;
        }
        return true;
    }

    @Override
    protected boolean doDisable() {
        log.info("Stopping Prometheus Exporter");
        if (prometheusClient != null) {
            prometheusClient.close();
            defaultRegistry.clear();
        }
        return true;
    }

    private String getEndpointScheme(boolean tlsEnabled){
        return tlsEnabled ? "https" : "http";
    }

    private HttpsConfigurator createHttpsConfigurator(String keystoreType, String keystoreFile, String keystorePassword) throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, KeyManagementException {
        KeyStore keystore = loadKeyStore(keystoreType, keystoreFile, keystorePassword);
        KeyManagerFactory keyManagerFactory = createKeyManagerFactory(keystore, keystorePassword);
        SSLContext sslContext = createSSLContext(keyManagerFactory);

        return new HttpsConfigurator(sslContext) {
            @Override
            public void configure(HttpsParameters params) {
                SSLEngine engine = sslContext.createSSLEngine();
                params.setNeedClientAuth(false);
                params.setCipherSuites(engine.getEnabledCipherSuites());
                params.setProtocols(engine.getEnabledProtocols());

                SSLParameters sslParameters = sslContext.getSupportedSSLParameters();
                params.setSSLParameters(sslParameters);
            }
        };
    }

    private KeyStore loadKeyStore(String keystoreType, String keystoreFile, String keystorePassword) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        KeyStore keyStore = KeyStore.getInstance(keystoreType);
        keyStore.load(new FileInputStream(keystoreFile), keystorePassword.toCharArray());

        return keyStore;
    }

    private KeyManagerFactory createKeyManagerFactory(KeyStore keyStore, String keystorePassword) throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(keyStore, keystorePassword.toCharArray());

        return keyManagerFactory;
    }

    private SSLContext createSSLContext(KeyManagerFactory keyManagerFactory) throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

        return sslContext;
    }
}
