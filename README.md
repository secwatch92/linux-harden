# linux-harden
This Bash script is designed to automate the process of hardening a Linux server (specifically Debian/Ubuntu). It aims to implement a set of standard security configurations and best practices to minimize the attack surface and enhance overall server security.

**Script's Core Functionality:**

1.  **Logging:** All script activities are logged to `/var/log/server_hardening.log`.
2.  **Randomized Variables:** Generates random usernames, passwords, SSH ports, and hostnames.
3.  **System Update:** Updates the operating system and software packages.
4.  **Root Password Change:** Changes the root user's password.
5.  **Package Installation:** Installs essential software packages for server management and security.
6.  **IPv6 Disabling:** Disables the IPv6 protocol (if not needed).
7.  **SSH Configuration:** Changes the SSH port, disables root login, and disables X11 Forwarding.
8.  **User Creation:** Creates a new user with limited privileges and a user with sudo access.
9.  **Hostname Change:** Changes the server's hostname.
10. **Fail2ban Configuration:** Configures Fail2ban to prevent brute-force attacks.
11. **UFW Configuration:** Configures the UFW firewall to restrict port access.
12. **hosts.allow/hosts.deny Configuration:** Restricts SSH access using `hosts.allow` and `hosts.deny`.
13. **Unnecessary Service Disabling:** Disables running services that are not required.
14. **Logrotate Configuration:** Manages log rotation.
15. **Automatic Security Updates:** Enables `unattended-upgrades` for automatic security updates.
16. **Hardening Test:** Checks the applied configurations.
17. **Temporary Execution:** Executes the script temporarily and deletes the original script after completion.

**Key Considerations:**

* This script is tailored for Debian/Ubuntu systems.
* Back up your server before running the script.
* Carefully configure `ALLOWED_HOSTS` and other variables.
* Securely store the `variables.txt` file and delete it after use.
* Ensure the `variables.txt` file has restrictive permissions (e.g., `chmod 600`).
* Use secure password management practices.
* Verify the output of commands to ensure successful execution.
* Deleting the original script after execution increases security, but be careful not to delete essential files.

**Script's Purpose:**

The primary goal of this script is to automate the Linux server hardening process and implement a set of standard security configurations to minimize the attack surface and enhance server security.

**Disclaimer:**

Use this script at your own risk. It is your responsibility to understand and modify the script as needed to fit your specific environment. Always test in a non-production environment first.
