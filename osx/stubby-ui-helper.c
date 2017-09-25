/**
 * stubby_ui_helper [-auth auth_key] [-config <config file path>] (start|stop|list|dns_stubby|dns_default|dns_list|check_config)
 *
 * A setuid application to accompany Stubby UI and do all the work that
 * requires privileges.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <Security/Authorization.h>
#include <os/log.h>

static const char LAUNCHCTL[] = "/bin/launchctl";
static const char STUBBY_SETDNS[] = "/usr/local/sbin/stubby-setdns-macos.sh";
static const char STUBBY[] = "/usr/local/bin/stubby";
static const char DEFAULT_CONFIG_FILE[] = "/usr/local/etc/stubby/stubby.yml";

void check_auth(const char *auth)
{
        return;
}

void usage()
{
        fprintf(stderr, "Usage: stubby_ui_helper [-auth <auth_key>] [-config <config file>] (start|stop|list|dns_stubby|dns_default|dns_list|check_config)\n");
        exit(1);
}

void fail_with_errno(const char *op)
{
        fprintf(stderr, "%s failed: %s.", op, strerror(errno));
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
                check_auth(auth);
                start();
        }
        else if (strcmp(cmd, "stop") == 0) {
                check_auth(auth);
                stop();
        }
        else if (strcmp(cmd, "list") == 0)
                list();
        else if (strcmp(cmd, "dns_stubby") == 0) {
                check_auth(auth);
                dns_stubby();
        }
        else if (strcmp(cmd, "dns_default") == 0) {
                check_auth(auth);
                dns_default();
        }
        else if (strcmp(cmd, "dns_list") == 0)
                dns_list();
        else if (strcmp(cmd, "check_config") == 0)
                check_config(config_file);

        /* If we get here, there's a problem... */
        usage();
}
