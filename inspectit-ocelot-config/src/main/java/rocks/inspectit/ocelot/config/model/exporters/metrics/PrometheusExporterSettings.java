package rocks.inspectit.ocelot.config.model.exporters.metrics;

import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;

/**
 * Settings for the OpenCensus Prometheus metrics exporter.
 */
@Data
@NoArgsConstructor
public class PrometheusExporterSettings {

    /**
     * If true, the inspectIT Agent will try to start a Prometheus metrics exporter.
     */
    private boolean enabled;

    /**
     * The hostname on which the /metrics endpoint of prometheus will be started.
     */
    @NotBlank
    private String host;

    /**
     * The port on which the /metrics endpoint of prometheus will be started.
     */
    @Min(0)
    @Max(65535)
    private int port;

    /**
     * If true, the inspectIT Agent will start a Prometheus metrics exporter that internally uses an HTTPS Server.
     *
     * If true, the properties {{@link #keyStoreType}}, {{@link #keyStoreFile}} and {{@link #keyStorePassword}}
     * have to be set.
     */
    private boolean tlsEnabled;

    /**
     * Defines the type of the keystore. Either 'JKS' or 'PKCS12'.
     * If {{@link #useSSL}} is set to 'true', it has to be set!
     */
    private String keyStoreType;

    /**
     * Defines the filepath of the keystore containing the certificate that will be used by the HTTPS Server
     * If {{@link #useSSL}} is set to 'true', it has to be set!
     */
    private String keyStoreFile;

    /**
     * Defines the password used to access the key in the keystore.
     * If {{@link #useSSL}} is set to 'true', it has to be set!
     */
    // TODO: change to byte[] for security reasons. Describe them
    private String keyStorePassword;
}
