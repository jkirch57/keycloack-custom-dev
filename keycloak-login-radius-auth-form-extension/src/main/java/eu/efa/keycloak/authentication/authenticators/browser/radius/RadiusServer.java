package eu.efa.keycloak.authentication.authenticators.browser.radius;

public class RadiusServer {
    private String ip;
    private String secret;
    private int timeout;

    public RadiusServer(String ip, String secret, int timeout) {
        super();
        this.ip = ip;
        this.secret = secret;
        this.timeout = timeout;
    }

    public int getTimeout() {
        return timeout;
    }

    public String getSecret() {
        return secret;
    }

    public String getIp() {
        return ip;
    }
}
