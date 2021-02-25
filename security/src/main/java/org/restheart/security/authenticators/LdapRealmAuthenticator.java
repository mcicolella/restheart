package org.restheart.security.authenticators;

import io.undertow.security.idm.Account;
import io.undertow.security.idm.Credential;
import io.undertow.security.idm.DigestCredential;
import io.undertow.security.idm.PasswordCredential;
import io.undertow.util.HexConverter;
import io.undertow.util.HttpString;
import static io.undertow.util.RedirectBuilder.UTF_8;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import org.mindrot.jbcrypt.BCrypt;
import org.restheart.ConfigurationException;
import org.restheart.cache.Cache;
import org.restheart.cache.CacheFactory;
import org.restheart.cache.LoadingCache;
import static org.restheart.plugins.ConfigurablePlugin.argValue;
import org.restheart.plugins.InjectConfiguration;
import org.restheart.plugins.InjectPluginsRegistry;
import org.restheart.plugins.PluginsRegistry;
import org.restheart.plugins.RegisterPlugin;
import org.restheart.plugins.security.Authenticator;
import org.restheart.security.PwdCredentialAccount;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Mauro Cicolella {@literal <info@emmecilab.net>}
 */
@RegisterPlugin(name = "ldapRealmAuthenticator",
        description = "authenticate requests against client credentials stored in ldap server")
public class LdapRealmAuthenticator implements Authenticator {

    private static final Logger LOGGER
            = LoggerFactory.getLogger(LdapRealmAuthenticator.class);

    public static final String X_FORWARDED_ACCOUNT_ID = "rhAuthenticator";
    public static final String X_FORWARDED_ROLE = "RESTHeart";

    private Boolean bcryptHashedPassword = false;
    Integer bcryptComplexity = 12;

    // Ldap configuration
    private final String initialContextFactory = "com.sun.jndi.ldap.LdapCtxFactory";
    private final int MAX_AUTHENTICATION_RESULT = 1;
    private String securityAuthentication = "simple";
    private String ldapServerUrl;
    private String searchBase = "dc=example,dc=com";
    private String managerDn;
    private String managerPassword;
    private String userSearchFilter;
    private boolean useCN;

    private Boolean cacheEnabled = false;
    private Integer cacheSize = 1_000; // 1000 entries
    private Integer cacheTTL = 60 * 1_000; // 1 minute
    private Cache.EXPIRE_POLICY cacheExpirePolicy
            = Cache.EXPIRE_POLICY.AFTER_WRITE;

    private LoadingCache<String, PwdCredentialAccount> USERS_CACHE = null;

    private static final transient Cache<String, String> USERS_PWDS_CACHE
            = CacheFactory.createLocalCache(
                    1_000l,
                    Cache.EXPIRE_POLICY.AFTER_READ,
                    20 * 60 * 1_000l);

    private PluginsRegistry registry;

    @InjectConfiguration
    public void setConf(Map<String, Object> args) {

        this.securityAuthentication = argValue(args, "security-authentication");
        this.ldapServerUrl = argValue(args, "ldap-server-url");
        this.searchBase = argValue(args, "search-base");
        this.managerDn = argValue(args, "manager-dn");
        this.managerPassword = argValue(args, "manager-password");
        this.cacheEnabled = argValue(args, "cache-enabled");
        this.cacheSize = argValue(args, "cache-size");
        this.cacheTTL = argValue(args, "cache-ttl");
        this.userSearchFilter = argValue(args, "user-search-filter");

        this.useCN = argValue(args, "use-cn");

        String _cacheExpirePolicy = argValue(args, "cache-expire-policy");
        if (_cacheExpirePolicy != null) {
            try {
                this.cacheExpirePolicy = Cache.EXPIRE_POLICY
                        .valueOf((String) _cacheExpirePolicy);
            } catch (IllegalArgumentException iae) {
                throw new ConfigurationException(
                        "wrong configuration file format. "
                        + "cache-expire-policy valid values are "
                        + Arrays.toString(Cache.EXPIRE_POLICY.values()));
            }
        }

        // set cache
        if (this.cacheEnabled) {
            this.USERS_CACHE = CacheFactory.createLocalLoadingCache(
                    this.cacheSize,
                    this.cacheExpirePolicy,
                    this.cacheTTL, (String key) -> {
                        return findAccount(accountIdTrasformer(key), null);
                    });
        }
    }

    @InjectPluginsRegistry
    public void setRegistry(PluginsRegistry registry) {
        this.registry = registry;
    }

    @Override
    public Account verify(Account account) {
        return account;
    }

    @Override
    public Account verify(String id, Credential credential) {
        if (credential == null) {
            LOGGER.debug("Cannot verify null credential");
            return null;
        }

        PwdCredentialAccount ref = getAccount(id, credential);
        if (ref != null) {
            updateAuthTokenCache(ref);
            return ref;
        } else {
            return null;
        }
    }

    /**
     * @return the bcryptComplexity
     */
    public Integer getBcryptComplexity() {
        return bcryptComplexity;
    }

    public boolean isBcryptHashedPassword() {
        return bcryptHashedPassword;
    }

    /**
     *
     * @param expectedPassword
     * @param credential
     * @return true if credential verifies successfully against ref account
     */
    private boolean verifyPasswordCredential(
            PwdCredentialAccount ref,
            PasswordCredential credential) {
        if (ref == null
                || ref.getPrincipal() == null
                || ref.getPrincipal().getName() == null
                || ref.getCredentials() == null
                || ref.getCredentials().getPassword() == null
                || credential == null || credential.getPassword() == null) {
            return false;
        }

        return checkPassword(
                ref.getPrincipal().getName(),
                this.bcryptHashedPassword,
                credential.getPassword(),
                ref.getCredentials().getPassword());
    }

    /**
     *
     * @param principalName
     * @param expectedPassword
     * @param credential
     * @return true if password verified successfully
     */
    private boolean verifyDigestCredential(
            PwdCredentialAccount ref,
            DigestCredential credential) {
        if (this.bcryptHashedPassword) {
            LOGGER.error("Digest authentication cannot support bcrypted stored "
                    + "password, consider using basic authetication over TLS");
            return false;
        }

        if (ref == null
                || ref.getCredentials() == null
                || ref.getCredentials().getPassword() == null
                || ref.getPrincipal() == null
                || ref.getPrincipal().getName() == null
                || credential == null) {
            return false;
        }

        try {
            MessageDigest digest = credential.getAlgorithm().getMessageDigest();

            digest.update(ref.getPrincipal().getName().getBytes(UTF_8));
            digest.update((byte) ':');
            digest.update(credential.getRealm().getBytes(UTF_8));
            digest.update((byte) ':');
            digest.update(new String(ref.getCredentials().getPassword()).getBytes(UTF_8));

            byte[] ha1 = HexConverter.convertToHexBytes(digest.digest());

            return credential.verifyHA1(ha1);
        } catch (NoSuchAlgorithmException ne) {
            LOGGER.error(ne.getMessage(), ne);
            return false;
        } catch (UnsupportedEncodingException usc) {
            LOGGER.error(usc.getMessage(), usc);
            return false;
        }
    }

    @Override
    public Account verify(Credential credential) {
        return null;
    }

    static boolean checkPassword(String username,
            boolean hashed,
            char[] password,
            char[] expected) {
        if (hashed) {
            if (username == null || password == null || expected == null) {
                return false;
            }

            var _password = new String(password);
            var _expected = new String(expected);

            // speedup bcrypted pwd check if already checked.
            // bcrypt check is very CPU intensive by design.
            var _cachedPwd = USERS_PWDS_CACHE.get(username.concat(_expected));

            if (_cachedPwd != null
                    && _cachedPwd.isPresent()
                    && _cachedPwd.get().equals(_password)) {
                return true;
            }

            try {
                boolean check = BCrypt.checkpw(_password, _expected);

                if (check) {
                    USERS_PWDS_CACHE.put(username.concat(_expected), _password);
                    return true;
                } else {
                    return false;
                }
            } catch (Throwable t) {
                USERS_PWDS_CACHE.invalidate(username.concat(_expected));
                LOGGER.warn("Error checking bcryped pwd hash", t);
                return false;
            }
        } else {
            return Arrays.equals(password, expected);
        }
    }

    private PwdCredentialAccount getAccount(String id, Credential credential) {

        if (USERS_CACHE == null) {

            if (credential instanceof PasswordCredential) {
                PasswordCredential pwd = (PasswordCredential) credential;
                return findAccount(this.accountIdTrasformer(id), String.valueOf(pwd.getPassword()));
            }
        } else {
            Optional<PwdCredentialAccount> _account = USERS_CACHE.getLoading(id);

            if (_account != null && _account.isPresent()) {
                return _account.get();
            } else {
                return null;
            }
        }
        return null;
    }

    /**
     * Override this method to trasform the account id. By default it returns
     * the id without any transformation. For example, it could be overridden to
     * force the id to be lowercase.
     *
     * @param id the account id
     * @return the trasformed account Id (default is identity)
     */
    protected String accountIdTrasformer(final String id) {
        return id;
    }

    /**
     * if client authenticates passing the real credentials, update the account
     * in the auth-token cache, otherwise the client authenticating with the
     * auth-token will not see roles updates until the cache expires (by default
     * TTL is 15 minutes after last request)
     *
     * @param account
     */
    private void updateAuthTokenCache(PwdCredentialAccount account) {
        try {
            var _tm = registry.getTokenManager();

            if (_tm != null) {
                var tm = _tm.getInstance();

                if (tm.get(account) != null) {
                    tm.update(account);
                }
            }
        } catch (ConfigurationException pce) {
            LOGGER.warn("error getting the token manager", pce);
        }
    }

    public static HttpString getXForwardedHeaderName(String suffix) {
        return HttpString.tryFromString("X-Forwarded-".concat(suffix));
    }

    public static HttpString getXForwardedAccountIdHeaderName() {
        return getXForwardedHeaderName("Account-Id");
    }

    public static HttpString getXForwardedRolesHeaderName() {
        return getXForwardedHeaderName("Account-Roles");
    }

    public PwdCredentialAccount findAccount(String accountId, String password) {
        Set<String> roles = authenticateLdapUser(accountId, password);

        if (roles != null) {
            return new PwdCredentialAccount(accountId, password.toCharArray(), roles);
        } else {
            return null;
        }
    }

    private Set<String> authenticateLdapUser(String username, String password) {
        DirContext ctx = bindUser(managerDn, managerPassword);
        String filter = userSearchFilter + "=" + username;
        Set<String> roles = null;

        try {
            List<SearchResult> results = searchInBase(ctx, searchBase, filter, MAX_AUTHENTICATION_RESULT);

            if (results.isEmpty()) {
                LOGGER.warn("User '" + username + "' not found in '" + ldapServerUrl + "'");
                return roles;
            }

            SearchResult searchResult = results.get(0);
            String userDn = searchResult.getNameInNamespace();
            LOGGER.info("Found user '{}' with DN '{}'", username, userDn);
            ctx = bindUser(userDn, password);
            if (ctx != null) {
                roles = getUserRoles(ctx, userDn);
                System.out.println(roles);
            }
        } catch (NamingException e) {
//TODO
        } finally {
            closeDirContext(ctx);
        }
        return roles;
    }

    private List<SearchResult> searchInBase(DirContext ctx, String base, String filter, int maxResults) throws NamingException {
        final List<SearchResult> results = new ArrayList<>();
        SearchControls ctrls = new SearchControls();

        ctrls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        ctrls.setTimeLimit(5000);
        ctrls.setCountLimit(maxResults);

        if (maxResults == 0) {
            return results;
        }

        NamingEnumeration<SearchResult> searchResults = null;
        try {
            LOGGER.warn("Searching user in search base '{}' using search filter '{}'", base, filter);
            searchResults = ctx.search(base, filter, ctrls);
            while (searchResults.hasMoreElements() && results.size() < maxResults) {
                results.add(searchResults.next());
            }

            //if (isHardLimitOnMaxResult && searchResults.hasMoreElements()) {
            //    throw new SearchResultLimitExceededException(maxResult, base);
            //}
        } finally {
            closeNamingEnumeration(searchResults);
        }
        return results;
    }

    private DirContext bindUser(String username, String password) {
        Hashtable<String, String> props = new Hashtable<>();
        props.put(Context.INITIAL_CONTEXT_FACTORY, initialContextFactory);
        props.put(Context.SECURITY_AUTHENTICATION, securityAuthentication);
        props.put(Context.PROVIDER_URL, ldapServerUrl);
        props.put(Context.SECURITY_PRINCIPAL, username);
        props.put(Context.SECURITY_CREDENTIALS, password);

        DirContext ctx = null;
        try {
            ctx = new InitialDirContext(props);
            LOGGER.info("Connected to '{}' as user '{}'", ldapServerUrl, username);
        } catch (javax.naming.CommunicationException ex) {
            LOGGER.warn("Failed to connect to '{}' caused by {}", ldapServerUrl, ex.getMessage());
        } catch (NamingException ex) {
            LOGGER.warn("Failed to authenticate user '{}' caused by {}", username, ex.getMessage());
            closeDirContext(ctx);
        }
        return ctx;
    }

    private void closeLdapContext(DirContext ctx) {
        try {
            ctx.close();
        } catch (NamingException ex) {
            LOGGER.warn("Error closing Ldap context cause by {}", ex.getMessage());
        }
    }

    void closeDirContext(DirContext ctx) {
        if (ctx == null) {
            return;
        }
        try {
            ctx.close();
        } catch (Exception e) {
            LOGGER.error("Error closing Ldap connection caused by {}", e.getMessage());
        }
    }

    void closeNamingEnumeration(NamingEnumeration namingEnumeration) {
        if (namingEnumeration == null) {
            return;
        }

        try {
            namingEnumeration.close();
        } catch (Exception e) {
            LOGGER.error("Error closing naming enumeration caused by {}", e.getMessage());
        }
    }

    private Set<String> getUserRoles(DirContext ctx, String username) throws NamingException {
        Set<String> roles = new HashSet<>();
        Map<String, String> groups = getLdapGroups(ctx);
        groups.entrySet().stream().filter(e -> e.getValue().contains(username)).forEach(e -> roles.add(e.getKey()));
        return roles;
    }

    private Map<String, String> getLdapGroups(DirContext ctx) throws NamingException {
        Map<String, String> groups = new HashMap<>();
        SearchControls searchControls = new SearchControls();
        String[] attrIDs = {"cn", "uniquemember"};
        searchControls.setReturningAttributes(attrIDs);
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        NamingEnumeration answer = ctx.search(searchBase, "(objectClass=groupOfUniqueNames)", searchControls);
        while (answer.hasMore()) {
            SearchResult rslt = (SearchResult) answer.next();
            Attributes attrs = rslt.getAttributes();
            String group = attrs.get("cn").toString();
            String[] groupName = group.split(":");
            String members = attrs.get("uniquemember").toString();
            String[] membersList = members.split(":");
            groups.put(groupName[1].strip().toLowerCase(), membersList[1].strip());
        }
        return groups;
    }

}

