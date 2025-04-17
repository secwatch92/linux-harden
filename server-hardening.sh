#!/bin/bash

# Define variables
LOG_FILE="/var/log/server_hardening.log"
SSH_CONFIG="/etc/ssh/sshd_config"
ALLOWED_HOSTS="Change"  # Set to the IP range you want to allow for SSH access // 192.168.1.0/24

# Function to log output
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a $LOG_FILE
}


# Check if we're running from the temporary copy
if [[ "$1" == "--from-temp" ]]; then
	log "✅ Running from temporary copy..."

	# Put your main script logic here
	log "🔧 Performing main operations..."

	# ------------------------
	# Randomized Configuration Variables with Special Characters
	# ------------------------
	Randomized_Configuration_Variables(){
		# Generate a random username (length 8-12 characters, first character must be a letter)
		NEW_USER=$(tr -dc 'a-z' < /dev/urandom | head -c 1)  # First character must be a letter
		NEW_USER+=$(tr -dc 'a-z0-9' < /dev/urandom | head -c 5)  # Next characters can be letters and numbers
		log "Creating new username $NEW_USER..."
		
		# Generate a random password for the new user (length 16) with special characters
		NEW_USER_PASSWORD=$(openssl rand -base64 240 | tr -dc 'a-zA-Z0-9@#$%^&+=_' | head -c 16)
		log "Generate a random password for the new user USER_PASSWORD ***********..."
		
		# Generate a random root username (length 8-12 characters, first character must be a letter)
		NEW_ROOT=$(tr -dc 'a-z' < /dev/urandom | head -c 1)  # First character must be a letter
		NEW_ROOT+=$(tr -dc 'a-z0-9' < /dev/urandom | head -c 5)  # Next characters can be letters and numbers
		log "Generate a random root username $NEW_ROOT..."

		# Generate a random password for the root user (length 16) with special characters
		NEW_ROOT_PASSWORD=$(openssl rand -base64 240 | tr -dc 'a-zA-Z0-9@#$%^&+=_' | head -c 16)
		log "Generate a random password for the root user ***********..."
		
		# Random SSH port number between 1024 and 65535
		NEW_SSH_PORT=$(shuf -i 10024-65535 -n 1)
		log "Random SSH port number $NEW_SSH_PORT ..."
		
		# Root password (16 characters) with special characters
		ROOT_PASSWORD=$(openssl rand -base64 240 | tr -dc 'a-zA-Z0-9@#$%^&+=_' | head -c 32)
		log "Creating new ROOT_PASSWORD ***********..."

		# Random hostname (example: my-server-<random_number>)
		NEW_HOSTNAME="my-$(openssl rand -base64 6 | tr -dc 'a-z0-9' | head -c 6)-server"
		log "Random hostname $NEW_HOSTNAME ..."

		# Get the server's IP address
		SERVER_IP=$(hostname -I | awk '{print $1}')
		log "Get the server's IP address $SERVER_IP ..."

		# ------------------------
		# File path for storing variables in root's home directory (using $HOME)
		# ------------------------

		VARIABLES_FILE="$HOME/variables.txt"

		# ------------------------
		# Save the generated values into a file
		# ------------------------

		echo "Generated Username: $NEW_USER" > $VARIABLES_FILE
		echo "Generated User Password: $NEW_USER_PASSWORD" >> $VARIABLES_FILE
		echo "Generated Root Username: $NEW_ROOT" >> $VARIABLES_FILE
		echo "Generated Root Password: $NEW_ROOT_PASSWORD" >> $VARIABLES_FILE
		echo "Generated SSH Port: $NEW_SSH_PORT" >> $VARIABLES_FILE
		echo "Generated Root Password: $ROOT_PASSWORD" >> $VARIABLES_FILE
		echo "Generated Hostname: $NEW_HOSTNAME" >> $VARIABLES_FILE
		echo "Server IP: $SERVER_IP" >> $VARIABLES_FILE
	}
	# ------------------------
	# Run Script
	# ------------------------
	# Function to update and upgrade system
	update_system() {
	    log "Updating and upgrading the system..."
	    apt update && apt upgrade -y
	    apt dist-upgrade -y
	    apt autoremove -y
	}

	# Function to change root password
	change_root_password() {
	    log "Changing root password..."
	    echo "root:$ROOT_PASSWORD" | chpasswd
	}

	# Function to install required packages
	install_packages() {
	    log "Installing required packages (nano, net-tools, tmux, curl, htop, auditd, fail2ban, unattended-upgrades, iputils-ping, iperf3, traceroute, speedtest-cli, sshpass)..."
	    apt install nano net-tools tmux curl htop auditd fail2ban unattended-upgrades iputils-ping iperf3 traceroute speedtest-cli sshpass -y
	}

	# Function to disable IPv6
	disable_ipv6() {
	    log "Disabling IPv6..."
	    # Add settings to disable IPv6 in sysctl.conf
	    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
	    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
	    echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
	    sysctl -p
	}

	# Function to configure SSH
	configure_ssh() {
	    log "Configuring SSH security..."
	    # Change the SSH port
	    sed -i "s/^#Port 22/Port $NEW_SSH_PORT/" $SSH_CONFIG
	    # sed -i "s/^#Port [0-9]\+/Port $NEW_SSH_PORT/" $SSH_CONFIG
	    # sed -i "s/^Port [0-9]\+/Port $NEW_SSH_PORT/" $SSH_CONFIG
	    # Disable root login via SSH
	    sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' $SSH_CONFIG
	    # Set X11Forwarding to no
	    sed -i 's/^X11Forwarding yes/X11Forwarding no/' $SSH_CONFIG
	    # Restart SSH to apply changes
	    systemctl restart sshd
	}

	# # Function to add a new user
	# add_new_user() {
	#     log "Creating new user $NEW_USER..."
	#     useradd -m -s /bin/bash $NEW_USER
	#     echo "$NEW_USER:$NEW_USER_PASSWORD" | chpasswd
	#     usermod -aG sudo $NEW_USER   # Optional: add user to sudo group
	#     log "Creating new user $NEW_ROOT..."
	# 	useradd -m -s /bin/bash $NEW_ROOT
	#     echo "$NEW_ROOT:$NEW_ROOT_PASSWORD" | chpasswd
	#     usermod -aG sudo $NEW_ROOT   # Optional: add user to sudo group
	# }
	# Function to add a new user with restricted privileges
	add_new_user() {
	    log "Creating new standard user $NEW_USER..."
	    useradd -m -s /bin/bash $NEW_USER
	    echo "$NEW_USER:$NEW_USER_PASSWORD" | chpasswd

	    # Allow only package installation for the new user
	    echo "$NEW_USER ALL=(ALL) NOPASSWD: /usr/bin/apt, /usr/bin/apt-get, /usr/bin/dpkg" | sudo tee /etc/sudoers.d/$NEW_USER

	    log "Creating new sudo user $NEW_ROOT..."
	    useradd -m -s /bin/bash $NEW_ROOT
	    echo "$NEW_ROOT:$NEW_ROOT_PASSWORD" | chpasswd
	    usermod -aG sudo $NEW_ROOT  # Grant full sudo privileges

	    log "User accounts configured successfully!"
	}


	# Function to change the hostname
	change_hostname() {
	    log "Changing hostname to $NEW_HOSTNAME..."
	    hostnamectl set-hostname $NEW_HOSTNAME
	    # Update /etc/hosts to reflect the new hostname
	    sed -i "s/127.0.1.1.*$/127.0.1.1   $NEW_HOSTNAME/" /etc/hosts
	}

	# Function to configure fail2ban
	install_fail2ban() {
	    log "Installing fail2ban..."
	    apt install fail2ban -y
	    systemctl enable fail2ban
	    systemctl start fail2ban
	    # Fail2ban default configuration for SSH
	    cat > /etc/fail2ban/jail.local <<EOL
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port    = $NEW_SSH_PORT
EOL
	    systemctl restart fail2ban
	}

	# Function to set up hosts.allow for SSH access control
	configure_hosts_allow() {
	    log "Configuring /etc/hosts.allow for SSH access control..."
	    echo "sshd: $ALLOWED_HOSTS" > /etc/hosts.allow
	    echo "sshd: 127.0.0.1" >> /etc/hosts.allow
	    #echo "sshd: 79.170.51.114" >> /etc/hosts.allow
	    # Deny all other access
	    echo "sshd: ALL" > /etc/hosts.deny
	}

	# Function to limit unnecessary services
	limit_services() {
	    log "Disabling unnecessary services..."
	    # List active services and disable ones that are not needed
	    for service in $(systemctl list-units --type=service --state=running | awk '{print $1}' | grep -vE 'ssh|cron|ufw|systemd|network'); do
		sudo systemctl stop $service
		sudo systemctl disable $service
	    done
	}

	# Function to monitor system resource usage
	install_monitoring_tools() {
	    log "Installing monitoring tools (htop)..."
	    apt install htop -y
	}

	# Function to configure log management (Logrotate)
	configure_log_management() {
	    log "Configuring log rotation..."
	    apt install logrotate -y
	    # Configure logrotate settings for server logs
	    cat > /etc/logrotate.d/server <<EOL
/var/log/*.log {
	daily
	rotate 7
	compress
	missingok
	notifempty
	create 640 root root
}
EOL
	}

	# Function to add current user to the sudo group
	add_current_user_to_sudo() {
	    log "Adding current user to sudo group..."
	    current_user=$(whoami)
	    usermod -aG sudo $current_user
	}

	# Module: Automatic Security Updates for Debian-based Systems

	enable_security_updates() {
	    echo "🔹 Enabling automatic security updates on Debian-based system..."

	    # Install unattended-upgrades if not installed
	    # sudo apt install unattended-upgrades -y

	    # Configure unattended-upgrades to only install security updates
	    sudo tee /etc/apt/apt.conf.d/50unattended-upgrades > /dev/null <<EOL
Unattended-Upgrade::Allowed-Origins {
	"Debian:security";
	"Ubuntu:security";
};
EOL

	    # Enable and start the unattended-upgrades service
	    sudo systemctl enable --now unattended-upgrades

	    # Add a cron job to run security updates daily at 3 AM
	    echo "0 3 * * * root /usr/bin/unattended-upgrade -d" | sudo tee /etc/cron.d/security-updates

	    echo "✅ Automatic security updates enabled!"
	}

	# Function to test the server hardening
	test_hardening() {
	    log "Testing server hardening..."

	    # Check if SSH is running with the correct port
	    ssh_status=$(ss -tuln | grep ":$NEW_SSH_PORT")
	    if [ -z "$ssh_status" ]; then
		log "Error: SSH is not running on port $NEW_SSH_PORT"
	    else
		log "SSH is running on port $NEW_SSH_PORT"
	    fi

	    # Check if root login is disabled
	    ssh_root_login=$(grep "PermitRootLogin no" $SSH_CONFIG)
	    if [ -z "$ssh_root_login" ]; then
		log "Error: Root login is not disabled in SSH configuration."
	    else
		log "Root login is disabled in SSH configuration."
	    fi

	    # Check if IPv6 is disabled
	    ipv6_status=$(sysctl net.ipv6.conf.all.disable_ipv6)
	    if [[ "$ipv6_status" == *"= 1"* ]]; then
		log "IPv6 is disabled."
	    else
		log "Error: IPv6 is not disabled."
	    fi

	    # Check fail2ban status
	    fail2ban_status=$(systemctl is-active fail2ban)
	    if [ "$fail2ban_status" != "active" ]; then
		log "Error: Fail2ban is not running."
	    else
		log "Fail2ban is running."
	    fi

	    # Check if the new user is added and has sudo privileges
	    user_sudo_check=$(sudo -l -U $NEW_USER)
	    if [[ "$user_sudo_check" == *"may run the following"* ]]; then
		log "New user $NEW_USER has sudo privileges."
	    else
		log "Error: New user $NEW_USER does not have sudo privileges."
	    fi
	}

	# Main script
	log "Starting server hardening..."

	# Randomized Configuration Variables
	Randomized_Configuration_Variables

	# Change root password
	change_root_password

	# Update and upgrade system
	update_system


	# Install required packages
	install_packages

	# Run the function if this script is executed directly

	enable_security_updates

	# Disable IPv6
	disable_ipv6

	# Configure SSH settings
	configure_ssh

	# Add new user
	add_new_user

	# Change hostname
	change_hostname

	# Install and configure fail2ban
	install_fail2ban

	# Configure /etc/hosts.allow
	configure_hosts_allow

	# Limit unnecessary services
	limit_services

	# Install monitoring tools
	install_monitoring_tools

	# Configure log management
	configure_log_management

	# Add current user to the sudo group
	add_current_user_to_sudo

	# Test server hardening
	test_hardening

	log "Server hardening completed successfully."
	# rm -- "$0"
	# Exit
	# exit 0


log "🧹 Deleting temporary file: $0"
    rm -- "$0"
    exit
fi

# If not running from temp, we're in the original script
log "🌀 Creating temporary copy..."

TMP_SCRIPT=$(mktemp /tmp/hardenflow.XXXXXX.sh)

# Copy this script to the temporary location
cp -- "$0" "$TMP_SCRIPT"
chmod +x "$TMP_SCRIPT"

log "🗑️ Deleting original script: $0"
rm -- "$0"

log "🚀 Executing temporary script..."
exec "$TMP_SCRIPT" --from-temp

