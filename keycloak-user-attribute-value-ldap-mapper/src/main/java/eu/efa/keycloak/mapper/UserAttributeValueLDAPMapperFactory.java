package eu.efa.keycloak.mapper;

import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.storage.ldap.LDAPConfig;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapperFactory;
import org.keycloak.storage.ldap.mappers.LDAPConfigDecorator;

import java.util.List;

public class UserAttributeValueLDAPMapperFactory extends AbstractLDAPStorageMapperFactory implements LDAPConfigDecorator {

    public static final String PROVIDER_ID = "user-attribute-value-ldap-mapper";
    protected static final List<ProviderConfigProperty> configProperties;

    static {
        List<ProviderConfigProperty> props = getConfigProps(null);
        configProperties = props;
    }

    static List<ProviderConfigProperty> getConfigProps(ComponentModel p) {
        String readOnly = "false";
        UserStorageProviderModel parent = new UserStorageProviderModel();
        if (p != null) {
            parent = new UserStorageProviderModel(p);
            LDAPConfig ldapConfig = new LDAPConfig(parent.getConfig());
            readOnly = ldapConfig.getEditMode() == UserStorageProvider.EditMode.WRITABLE ? "false" : "true";
        }
        ProviderConfigurationBuilder config = ProviderConfigurationBuilder.create()
                .property().name(UserAttributeValueLDAPMapper.USER_MODEL_ATTRIBUTE)
                .label("User Model Attribute")
                .helpText("Name of the UserModel property or attribute you want to map the LDAP attribute into. For example 'firstName', 'lastName, 'email', 'street' etc.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property().name(UserAttributeValueLDAPMapper.LDAP_ATTRIBUTE).label("LDAP Attribute").helpText("Name of mapped attribute on LDAP object. For example 'cn', 'sn, 'mail', 'street' etc.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property().name(UserAttributeValueLDAPMapper.LDAP_VALUE_ATTRIBUTE).label("LDAP Value Attribute").helpText("Value of mapped attribute on LDAP object.")
                .type(ProviderConfigProperty.MULTIVALUED_STRING_TYPE)
                .add()
                .property().name(UserAttributeValueLDAPMapper.USER_MODEL_VALUE_ATTRIBUTE)
                .label("User Model Value Attribute")
                .helpText("Value of the UserModel property or attribute you want to map with LDAP Value attribute into.")
                .type(ProviderConfigProperty.MULTIVALUED_STRING_TYPE)
                .add()
                .property().name(UserAttributeValueLDAPMapper.READ_ONLY).label("Read Only")
                .helpText("Read-only attribute is imported from LDAP to UserModel, but it's not saved back to LDAP when user is updated in Keycloak.")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue(readOnly)
                .add();
        if (parent.isImportEnabled()) {
            config.
                    property().name(UserAttributeValueLDAPMapper.ALWAYS_READ_VALUE_FROM_LDAP).label("Always Read Value From LDAP")
                    .helpText("If on, then during reading of the LDAP attribute value will always used instead of the value from Keycloak DB")
                    .type(ProviderConfigProperty.BOOLEAN_TYPE).defaultValue("false").add();
        }
        config.property().name(UserAttributeValueLDAPMapper.IS_MANDATORY_IN_LDAP).label("Is Mandatory In LDAP")
                .helpText("If true, attribute is mandatory in LDAP. Hence if there is no value in Keycloak DB, the empty value will be set to be propagated to LDAP")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false").add()
                .property().name(UserAttributeValueLDAPMapper.IS_BINARY_ATTRIBUTE).label("Is Binary Attribute")
                .helpText("Should be true for binary LDAP attributes")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false").add();
        return config.build();
    }

    @Override
    public String getHelpText() {
        return "Used to map single attribute from LDAP user to attribute of UserModel in Keycloak DB";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config) throws ComponentValidationException {
        checkMandatoryConfigAttribute(UserAttributeValueLDAPMapper.USER_MODEL_ATTRIBUTE, "User Model Attribute", config);
        checkMandatoryConfigAttribute(UserAttributeValueLDAPMapper.LDAP_ATTRIBUTE, "LDAP Attribute", config);
        checkMandatoryConfigAttribute(UserAttributeValueLDAPMapper.LDAP_VALUE_ATTRIBUTE, "LDAP Value Attribute", config);
        checkMandatoryConfigAttribute(UserAttributeValueLDAPMapper.USER_MODEL_VALUE_ATTRIBUTE, "User Model Value Attribute", config);

        boolean isBinaryAttribute = config.get(UserAttributeValueLDAPMapper.IS_BINARY_ATTRIBUTE, false);
        boolean alwaysReadValueFromLDAP = config.get(UserAttributeValueLDAPMapper.ALWAYS_READ_VALUE_FROM_LDAP, false);
        if (isBinaryAttribute && !alwaysReadValueFromLDAP) {
            throw new ComponentValidationException("With Binary attribute enabled, the ''Always read value from LDAP'' must be enabled too");
        }

        if (config.getConfig().getList(UserAttributeValueLDAPMapper.LDAP_VALUE_ATTRIBUTE).size() !=
                config.getConfig().getList(UserAttributeValueLDAPMapper.USER_MODEL_VALUE_ATTRIBUTE).size()) {
            throw new ComponentValidationException("LDAP and User Model attribute list should have the same size");
        }
    }

    @Override
    protected AbstractLDAPStorageMapper createMapper(ComponentModel mapperModel, LDAPStorageProvider federationProvider) {
        return new UserAttributeValueLDAPMapper(mapperModel, federationProvider);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties(RealmModel realm, ComponentModel parent) {
        return getConfigProps(parent);
    }


    @Override
    public void updateLDAPConfig(LDAPConfig ldapConfig, ComponentModel mapperModel) {
        boolean isBinaryAttribute = mapperModel.get(UserAttributeValueLDAPMapper.IS_BINARY_ATTRIBUTE, false);
        if (isBinaryAttribute) {
            String ldapAttrName = mapperModel.getConfig().getFirst(UserAttributeValueLDAPMapper.LDAP_ATTRIBUTE);
            ldapConfig.addBinaryAttribute(ldapAttrName);
        }
    }
}