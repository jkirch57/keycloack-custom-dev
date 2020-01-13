package eu.efa.keycloak.authentication.authenticators.browser.radius;

import org.tinyradius.packet.AccessRequest;
import org.tinyradius.packet.RadiusPacket;
import org.tinyradius.util.RadiusClient;
import org.tinyradius.util.RadiusException;

import java.io.IOException;
import java.net.SocketException;

public class RadiusServerAccess {
    private RadiusClient radiusClient;

    public RadiusServerAccess(RadiusServer radiusServer) {
        this.radiusClient = initRadiusClient(radiusServer);
    }

    private RadiusClient initRadiusClient(RadiusServer radiusServer) {
        try {
            RadiusClient radiusClient = new RadiusClient(radiusServer.getIp(), radiusServer.getSecret());
            radiusClient.setSocketTimeout(radiusServer.getTimeout());
            radiusClient.setAuthPort(1645);
            radiusClient.setRetryCount(1);
            return radiusClient;
        } catch (SocketException e) {
            throw new IllegalStateException(e);
        }
    }

    public RadiusPacket authenticate(String login, String password) throws IOException, RadiusException {
        AccessRequest ar = new AccessRequest(login, password);
        ar.setAuthProtocol(AccessRequest.AUTH_PAP);

        RadiusPacket response = radiusClient.authenticate(ar);
        return response;
    }
}
