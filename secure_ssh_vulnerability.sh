#!/bin/bash

# Backup the script if the backup doesn't already exist
SCRIPT_PATH="$(realpath "$0")"  # Get the full path to the current script
BACKUP_PATH="${SCRIPT_PATH}.bak"

if [ -f "$BACKUP_PATH" ]; then
    echo "Backup already exists: $BACKUP_PATH"
else
    echo "Creating backup of the script at $BACKUP_PATH"
    cp "$SCRIPT_PATH" "$BACKUP_PATH"
fi

# Script to create a weak but harder-to-detect SSH configuration vulnerability
# Now enhanced with Fail2ban and periodic random port changes

# Function to check if a package is installed
function check_and_install {
    PACKAGE=$1
    if dpkg -s "$PACKAGE" >/dev/null 2>&1; then
        echo "$PACKAGE is already installed."
    else
        echo "Installing $PACKAGE..."
        sudo apt install -y "$PACKAGE"
    fi
}

# Update package list
echo "Updating package list..."
sudo apt update

# Check and install OpenSSH Server if not installed
check_and_install "openssh-server"

# Generate a random port number between 2000 and 5000
RANDOM_PORT=$((2000 + RANDOM % 3000))
echo "Configuring SSH to use a random port: $RANDOM_PORT"

# Update SSH configuration to listen on the random port
sudo sed -i "s/^Port [0-9]*/Port $RANDOM_PORT/" /etc/ssh/sshd_config

# Enable password authentication and root login
echo "Enabling password authentication and root login..."
sudo sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo sed -i 's/^#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
sudo sed -i 's/^PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config

# Disable SSH key-based authentication (optional but adds to weakness)
echo "Disabling SSH key-based authentication..."
sudo sed -i 's/^#PubkeyAuthentication yes/PubkeyAuthentication no/' /etc/ssh/sshd_config

# Add a misleading banner to SSH
echo "Creating a misleading SSH banner..."
echo "Unauthorized access is strictly prohibited. All activities are logged and monitored. Do not try any common passwords" | sudo tee /etc/ssh/ssh_banner > /dev/null
sudo sed -i 's/^#Banner none/Banner \/etc\/ssh\/ssh_banner/' /etc/ssh/sshd_config

# Limit login attempts and reduce login grace time
echo "Limiting login attempts and grace time..."
echo "MaxAuthTries 3" | sudo tee -a /etc/ssh/sshd_config > /dev/null
echo "LoginGraceTime 20" | sudo tee -a /etc/ssh/sshd_config > /dev/null

# Hide the SSH version (disable banner version info)
echo "Hiding the SSH version..."
sudo sed -i 's/^#DebianBanner yes/DebianBanner no/' /etc/ssh/sshd_config

# Check if weakuser exists before adding
if id "weakuser" &>/dev/null; then
    echo "User weakuser already exists."
else
    sudo adduser --disabled-password --gecos "" weakuser
    echo "weakuser:password123" | sudo chpasswd
    echo "Created weakuser with password: password123"
fi

# Restart SSH service to apply the changes
echo "Restarting SSH service..."
sudo systemctl daemon-reload
sudo systemctl restart ssh

# Detect and remove all existing SSH-related UFW rules
echo "Removing all old UFW SSH rules..."
for rule in $(sudo ufw status | grep 'ALLOW' | grep 'tcp' | awk '{print $1}' | sort -u); do
    echo "Removing UFW rule for $rule"
    sudo ufw delete allow $rule
done

# Optional: Enable UFW and allow the new SSH port (random port selected)
echo "Setting up UFW to allow new SSH port ($RANDOM_PORT)..."
sudo ufw allow $RANDOM_PORT/tcp
sudo ufw enable

# Check and install Fail2ban if not installed
check_and_install "fail2ban"

# Configure Fail2ban to block SSH attackers
echo "[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 600
findtime = 600" | sudo tee /etc/fail2ban/jail.local > /dev/null

# Restart Fail2ban service
sudo systemctl restart fail2ban

# Add a 5-second delay to SSH login attempts to slow down brute-force attacks (tarpitting)
echo "Adding delay for failed SSH login attempts..."
sudo sed -i '/^auth.*pam_faildelay.so/d' /etc/pam.d/sshd
echo "auth required pam_faildelay.so delay=5000000" | sudo tee -a /etc/pam.d/sshd > /dev/null

# Create a cron job to change SSH port every 12 hours
echo "Setting up cron job for SSH port randomization..."
sudo tee /usr/local/bin/change_ssh_port.sh > /dev/null <<EOL
#!/bin/bash
NEW_PORT=\$((2000 + RANDOM % 3000))
sudo sed -i "s/^Port [0-9]*/Port \$NEW_PORT/" /etc/ssh/sshd_config
sudo systemctl restart ssh
echo "SSH port changed to: \$NEW_PORT at \$(date)" | sudo tee -a /var/log/ssh_port_changes.log
sudo ufw delete allow ssh
sudo ufw allow \$NEW_PORT/tcp
sudo ufw reload
EOL

# Make the randomization script executable
sudo chmod +x /usr/local/bin/change_ssh_port.sh

# Set up the cron job to run every 12 hours
(crontab -l 2>/dev/null; echo "0 */12 * * * /usr/local/bin/change_ssh_port.sh") | sudo crontab -

# Final restart to ensure all changes are applied
echo "Final restart of SSH service to apply all changes..."
sudo systemctl restart ssh

echo "SSH vulnerability setup complete on port $RANDOM_PORT with Tarpitting and Fail2ban!"
