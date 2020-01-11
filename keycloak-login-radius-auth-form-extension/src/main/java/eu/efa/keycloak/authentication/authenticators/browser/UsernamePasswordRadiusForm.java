package eu.efa.keycloak.authentication.authenticators.browser;

import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.common.ClientConnection;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.PasswordCredentialProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.forms.login.freemarker.model.LoginBean;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.util.CookieHelper;
import org.keycloak.utils.MediaType;

import javax.ws.rs.core.*;

public class UsernamePasswordRadiusForm extends AbstractUsernameFormAuthenticator implements Authenticator, CredentialValidator<PasswordCredentialProvider> {
    private static final String RADIUS_PUSH_OPTION_VALUE = "push";
    private static final String LOGIN_RADIUS = "login-radius.ftl";
    private static final String RADIUS_PUSH_PASSCODE = "p";

    protected static ServicesLogger log = ServicesLogger.LOGGER;

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            return;
        }
        if (!validateForm(context, formData)) {
            return;
        }


        context.success();
    }

    private boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        return validateUserAndPassword(context, formData) && validateRadius(context, formData);
    }

    private boolean validateRadius(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        String tokenType = formData.getFirst("tokentype");
        String passcode = formData.getFirst("passcode");

        if (RADIUS_PUSH_OPTION_VALUE.equals(tokenType)) {
            passcode = RADIUS_PUSH_PASSCODE;
        }

        boolean radiusRet = radiusServerCall(context.getUser().getUsername(), passcode);

        if (radiusRet) {
            if (context.getRealm().isRememberMe() && "on".equalsIgnoreCase(formData.getFirst("rememberMe"))) {
                createRadiusOptionRememberMeCookies(context.getRealm(), tokenType, context.getUriInfo(), context.getConnection());
            } else {
                expireRadiusOptionRememberMeCookies(context.getRealm(), context.getUriInfo(), context.getConnection());
            }
        }
        return radiusRet;
    }

    private void createRadiusOptionRememberMeCookies(RealmModel realm, String radiusOption, UriInfo uriInfo, ClientConnection connection) {
            String path = AuthenticationManager.getRealmCookiePath(realm, uriInfo);
            boolean secureOnly = realm.getSslRequired().isRequired(connection);
            CookieHelper.addCookie("KEYCLOAK_RADIUS_REMEMBER_ME", "radius:" + radiusOption, path, (String)null, (String)null, 31536000, secureOnly, true);
    }

    private void expireRadiusOptionRememberMeCookies(RealmModel realm, UriInfo uriInfo, ClientConnection connection) {
        String path = AuthenticationManager.getRealmCookiePath(realm, uriInfo);
        AuthenticationManager.expireCookie(realm, "KEYCLOAK_RADIUS_REMEMBER_ME", path, true, connection);
    }

    private boolean radiusServerCall(String username, String passcode) {
        log.info("Call radius server");
        return true;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
        String loginHint = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);

        String rememberMeUsername = AuthenticationManager.getRememberMeUsername(context.getRealm(), context.getHttpRequest().getHttpHeaders());
        String rememberMeRadius = getRememberMeRadius(context.getRealm(), context.getHttpRequest().getHttpHeaders());

        if (loginHint != null || rememberMeUsername != null) {
            if (loginHint != null) {
                formData.add(AuthenticationManager.FORM_USERNAME, loginHint);
            } else {
                formData.add(AuthenticationManager.FORM_USERNAME, rememberMeUsername);
                formData.add("radius", rememberMeRadius);
                formData.add("rememberMe", "on");
            }
        }
        Response challengeResponse = challenge(context, formData);
        context.challenge(challengeResponse);
    }

    public static String getRememberMeRadius(RealmModel realm, HttpHeaders headers) {
        if (realm.isRememberMe()) {
            Cookie cookie = (Cookie)headers.getCookies().get("KEYCLOAK_RADIUS_REMEMBER_ME");
            if (cookie != null) {
                String value = cookie.getValue();
                String[] s = value.split(":");
                if (s[0].equals("radius") && s.length == 2) {
                    return s[1];
                }
            }
        }

        return null;
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        LoginFormsProvider forms = context.form();

        if (formData.size() > 0) forms.setFormData(formData);

        forms.setMediaType(MediaType.TEXT_HTML_UTF_8_TYPE)
                .setAttribute("login", new LoginBean(formData));

        if (formData.containsKey("radius")) {
            forms.setAttribute("radius", formData.getFirst("radius"));
        }

        return forms.createForm(LOGIN_RADIUS);
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        // never called
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // never called
    }

    @Override
    public void close() {

    }

    @Override
    public PasswordCredentialProvider getCredentialProvider(KeycloakSession session) {
        return (PasswordCredentialProvider) session.getProvider(CredentialProvider.class, "keycloak-password");
    }
}