/**
 * stubby_ui_helper [-auth auth_key] [-config <config file path>] (start|stop|list|dns_stubby|dns_default|dns_list|check_config)
 *
 * A setuid application to accompany Stubby UI and do all the work that
 * requires privileges.
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <Security/Authorization.h>
#include <os/log.h>

static const char CP[] = "/bin/cp";
static const char LAUNCHCTL[] = "/bin/launchctl";
static const char STUBBY_SETDNS[] = "/usr/local/sbin/stubby-setdns-macos.sh";
static const char STUBBY[] = "/usr/local/bin/stubby";
static const char DEFAULT_CONFIG_FILE[] = "/usr/local/etc/stubby/stubby.yml";

static const char RIGHT_DAEMON_RUN[] = "net.getdnsapi.stubby.daemon.run";
static const char RIGHT_DNS_LOCAL[] = "net.getdnsapi.stubby.dns.local";

void check_auth(const char *auth, const char *right)
{
        if (!auth) {
                fprintf(stderr, "Authorization required.");
                os_log(OS_LOG_DEFAULT, "Required authorization not supplied.");
                exit(1);
        }

        AuthorizationExternalForm auth_ext_form;
        for (size_t i = 0; i < kAuthorizationExternalFormLength; ++i) {
                char c = 0;

                if (isxdigit(*auth)) {
                        char n = (*auth >= 'a') ? *auth + 10 - 'a' : *auth - '0';
                        c |= (n << 4);
                        ++auth;
                        if (isxdigit(*auth)) {
                                n = (*auth >= 'a') ? *auth + 10 - 'a' : *auth - '0';
                                c |= n;
                                ++auth;
                                auth_ext_form.bytes[i] = c;
                                continue;
                        }
                }
                fprintf(stderr, "Invalid authorization key text.");
                os_log(OS_LOG_DEFAULT, "Invalid authorization key test.");
                exit(1);
        }

        AuthorizationRef auth_ref;
        OSStatus oss;

        oss = AuthorizationCreateFromExternalForm(&auth_ext_form, &auth_ref);
        if (oss != errAuthorizationSuccess) {
                fprintf(stderr, "Bad authorization key form.");
                os_log(OS_LOG_DEFAULT, "Authorization key is of wrong form.");
                exit(1);
        }

        AuthorizationItem one_right = { right, 0, NULL, 0 };
        AuthorizationRights rights = { 1, &one_right };

        oss = AuthorizationCopyRights(
                auth_ref,
                &rights,
                kAuthorizationEmptyEnvironment,
                kAuthorizationFlagExtendRights | kAuthorizationFlagInteractionAllowed,
                NULL);
        if (oss != errAuthorizationSuccess) {
                fprintf(stderr, "Authorization declined.");
                os_log(OS_LOG_DEFAULT, "Authorization declined.");
                exit(1);
        }

        AuthorizationFree(auth_ref, kAuthorizationFlagDefaults);
}

void usage()
{
        fprintf(stderr, "Usage: stubby_ui_helper [-auth <auth_key>] [-config <config file>] (start|stop|list|dns_stubby|dns_default|dns_list|check_config|write_config)\n");
        exit(1);
}

void fail_with_errno(const char *op)
{
        fprintf(stderr, "%s failed: %s.\n", op, strerror(errno));
        os_log(OS_LOG_DEFAULT, "%s failed: %s.", op, strerror(errno));
        exit(1);
}

void start()
{
        os_log(OS_LOG_DEFAULT, "Starting Stubby.");

        int err = execl(LAUNCHCTL, LAUNCHCTL, "load", "/Library/LaunchDaemons/org.getdns.stubby.plist", NULL);
        if (err == -1)
                fail_with_errno("start");
}

void stop()
{
        os_log(OS_LOG_DEFAULT, "Stopping Stubby.");

        int err = execl(LAUNCHCTL, LAUNCHCTL, "unload", "/Library/LaunchDaemons/org.getdns.stubby.plist", NULL);
        if (err == -1)
                fail_with_errno("stop");
}

void list()
{
        os_log(OS_LOG_DEFAULT, "Checking Stubby.");

        int err = execl(LAUNCHCTL, LAUNCHCTL, "list", "org.getdns.stubby", NULL);
        if (err == -1)
                fail_with_errno("stop");
}

void dns_stubby()
{
        os_log(OS_LOG_DEFAULT, "DNS resolving via Stubby.");

        int err = execl(STUBBY_SETDNS, STUBBY_SETDNS, NULL);
        if (err == -1)
                fail_with_errno("dns_stubby");
}

void dns_default()
{
        os_log(OS_LOG_DEFAULT, "DNS resolving via defaults.");

        int err = execl(STUBBY_SETDNS, STUBBY_SETDNS, "-r", NULL);
        if (err == -1)
                fail_with_errno("dns_default");
}

void dns_list()
{
        os_log(OS_LOG_DEFAULT, "List DNS resolver.");

        int err = execl(STUBBY_SETDNS, STUBBY_SETDNS, "-l", NULL);
        if (err == -1)
                fail_with_errno("dns_list");
}

void check_config(const char *config_file)
{
        os_log(OS_LOG_DEFAULT, "Check configuration.");

        int err = execl(STUBBY, STUBBY, "-C", config_file, "-i", NULL);
        if (err == -1)
                fail_with_errno("check_config");
}

void write_config(const char *config_file)
{
        os_log(OS_LOG_DEFAULT, "Write configuration.");

        int err = execl(CP, CP, config_file, DEFAULT_CONFIG_FILE, NULL);
        if (err == -1)
                fail_with_errno("write_config");
}


int main(int ac, char *av[])
{
        const char *auth = NULL;
        const char *cmd = NULL;
        const char *config_file = DEFAULT_CONFIG_FILE;

        ac--;
        av++;

        for (;;) {
                if (ac < 2)
                        break;

                if (strcmp(av[0], "-auth") == 0)
                        auth = av[1];
                else if (strcmp(av[0], "-config") == 0)
                        config_file = av[1];
                else
                        usage();
                av += 2;
                ac -= 2;
        }

        if (ac != 1)
                usage();
        cmd = av[0];

        if (setuid(0) == -1)
                fail_with_errno("setuid");

        if (strcmp(cmd, "start") == 0) {
                check_auth(auth, RIGHT_DAEMON_RUN);
                start();
        }
        else if (strcmp(cmd, "stop") == 0) {
                check_auth(auth, RIGHT_DAEMON_RUN);
                stop();
        }
        else if (strcmp(cmd, "list") == 0)
                list();
        else if (strcmp(cmd, "dns_stubby") == 0) {
                check_auth(auth, RIGHT_DNS_LOCAL);
                dns_stubby();
        }
        else if (strcmp(cmd, "dns_default") == 0) {
                check_auth(auth, RIGHT_DNS_LOCAL);
                dns_default();
        }
        else if (strcmp(cmd, "dns_list") == 0)
                dns_list();
        else if (strcmp(cmd, "check_config") == 0)
               check_config(config_file);
        else if (strcmp(cmd, "write_config") == 0)
                write_config(config_file);

        /* If we get here, there's a problem... */
        usage();
}
