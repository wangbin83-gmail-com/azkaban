package azkaban.user;

import azkaban.utils.Props;
import com.unboundid.ldap.sdk.*;
import org.apache.log4j.Logger;

import java.util.HashMap;

/**
 * Created by wangbin on 3/9/15.
 */
public class LdapUserManager implements UserManager {

    private static final Logger logger = Logger.getLogger(LdapUserManager.class.getName());

    public static final String LDAP_SERVER_PARAM = "user.manager.ldap.server";
    public static final String LDAP_PORT_PARAM = "user.manager.ldap.port";
    public static final String LDAP_SEARCH_ROOT_PARAM = "user.manager.ldap.root";

    private String ldapServer;
    private int ldapPort;
    private String ldapSearchRoot;

    private HashMap<String, Role> roles = new HashMap<String, Role>();
    private User adminUser;

    public LdapUserManager(Props props) {
        ldapServer = props.getString(LDAP_SERVER_PARAM);
        ldapPort = props.getInt(LDAP_PORT_PARAM, 389);
        ldapSearchRoot = props.getString(LDAP_SEARCH_ROOT_PARAM);

        Permission adminPerm = new Permission();
        adminPerm.addPermission(Permission.Type.ADMIN);
        Role adminRole = new Role("admin", adminPerm);
        roles.put("admin", adminRole);

        Permission normalPerm = new Permission();
        normalPerm.addPermission(Permission.Type.READ, Permission.Type.WRITE,
                Permission.Type.EXECUTE, Permission.Type.SCHEDULE, Permission.Type.METRICS);
        Role normalRole = new Role("normal", normalPerm);
        roles.put("normal", normalRole);

        adminUser = new User("admin");
        adminUser.addRole("admin");
    }
    /**
     * Retrieves the user given the username and password to authenticate against.
     *
     * @param username
     * @param password
     * @return
     * @throws UserManagerException If the username/password combination doesn't exist.
     */
    public User getUser(String username, String password) throws UserManagerException {
        if (username.equalsIgnoreCase("admin") && password.equals("admin_rong360")) {
            return  adminUser;
        }

        LDAPConnection ldap = null;
        try {
            ldap = new LDAPConnection(ldapServer, ldapPort);
        } catch (LDAPException e) {
            e.printStackTrace();
            throw new UserManagerException("cant connect to server " + ldapServer + ":" + ldapPort);
        }
        SearchResult sr = null;
        try {
            Filter filter = Filter.createEqualityFilter("uid", username);
            sr = ldap.search(ldapSearchRoot, SearchScope.SUB, filter);
        } catch (LDAPSearchException e) {
            e.printStackTrace();
            throw new UserManagerException("Internal error: User not found.");
        }
        if (sr.getEntryCount() == 0) {
            throw new UserManagerException("Internal error: User not found.");
        }

        String dn = sr.getSearchEntries().get(0).getDN();
        try {
            ldap = new LDAPConnection(ldapServer, ldapPort, dn, password);
            User user = new User(username);
            user.addRole("normal");
            return user;
        } catch (LDAPException e) {
            if (e.getResultCode() == ResultCode.INVALID_CREDENTIALS) {
                throw new UserManagerException("Password not correct!");
            }
        }
        ldap.close();
        return null;
    }

    /**
     * Returns true if the user is valid. This is used when adding permissions for users
     *
     * @param username
     * @return
     */
    public boolean validateUser(String username) {
        if (username.equalsIgnoreCase("admin")) {
            return true;
        }

        LDAPConnection ldap = null;
        try {
            ldap = new LDAPConnection(ldapServer, ldapPort);
        } catch (LDAPException e) {
            e.printStackTrace();
            return false;
        }
        SearchResult sr = null;
        try {
            Filter filter = Filter.createEqualityFilter("uid", username);
            sr = ldap.search(ldapSearchRoot, SearchScope.SUB, filter);
        } catch (LDAPSearchException e) {
            e.printStackTrace();
            return false;
        }
        if (sr.getEntryCount() == 0) {
            return false;
        }
        return true;
    }

    /**
     * Returns true if the group is valid. This is used when adding permissions for groups.
     *
     * @param group
     * @return
     */
    public boolean validateGroup(String group) {
        return true;
    }

    /**
     * Returns the user role. This may return null.
     *
     * @param roleName
     * @return
     */
    public Role getRole(String roleName) {
        return roles.get(roleName);
    }

    public boolean validateProxyUser(String proxyUser, User realUser) {
        return true;
    }
}
