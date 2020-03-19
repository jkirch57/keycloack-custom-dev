package eu.efa.keycloak.events;

import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class AuditTrailEventListenerProvider implements EventListenerProvider {
    private Set<EventType> eventTypeToAudit = new HashSet<>(Arrays.asList(EventType.CLIENT_LOGIN, EventType.LOGOUT));
    private KeycloakSession keycloakSession;

    public AuditTrailEventListenerProvider(KeycloakSession keycloakSession) {
        this.keycloakSession = keycloakSession;
    }

    @Override
    public void onEvent(Event event) {
        //System.out.println(keycloakSession.getContext().getClient().getClientId());
        System.out.println(keycloakSession.users().getUserById(event.getUserId(), keycloakSession.getContext().getRealm()).getUsername());
        System.out.println(event.getType());
        if (eventTypeToAudit.contains(event.getType())) {
            System.out.println("Event Occurred:" + toString(event));
        };
    }

    private String toString(Event event) {
        StringBuilder sb = new StringBuilder();
        sb.append("type=");
        sb.append(event.getType());
        sb.append(", realmId=");
        sb.append(event.getRealmId());
        sb.append(", clientId=");
        sb.append(event.getClientId());
        sb.append(", userId=");
        sb.append(event.getUserId());
        sb.append(", ipAddress=");
        sb.append(event.getIpAddress());

        if (event.getError() != null) {
            sb.append(", error=");
            sb.append(event.getError());
        }

        if (event.getDetails() != null) {
            for (Map.Entry<String, String> e : event.getDetails().entrySet()) {
                sb.append(", ");
                sb.append(e.getKey());
                if (e.getValue() == null || e.getValue().indexOf(' ') == -1) {
                    sb.append("=");
                    sb.append(e.getValue());
                } else {
                    sb.append("='");
                    sb.append(e.getValue());
                    sb.append("'");
                }
            }
        }
        return sb.toString();
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean b) {

    }

    @Override
    public void close() {

    }
}
