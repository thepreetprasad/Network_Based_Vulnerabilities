#!/bin/bash

# Define the Samba user and trick file location
REAL_USER="user1"
TRICK_FILE="/srv/samba/sensitive_information/trick.txt"
SAMBA_CONF="/etc/samba/smb.conf"

# Generate random ports for the decoy and real shares
DECOY_PORT=$((1025 + RANDOM % 64511))
REAL_PORT=$((1025 + RANDOM % 64511))

# Define directories for the two shares
DECOY_DIR="/srv/samba/sensitive_information"
REAL_DIR="/srv/samba/vulnerable_share"

# Function to check if a package is installed, if not, install it
check_and_install() {
    PACKAGE=$1
    if dpkg -s "$PACKAGE" >/dev/null 2>&1; then
        echo "$PACKAGE is already installed."
    else
        echo "Installing $PACKAGE..."
        sudo apt-get install -y "$PACKAGE"
    fi
}

# Function to generate a random password
generate_password() {
    # Generate a random password of 12 characters (alphanumeric)
    echo $(tr -dc A-Za-z0-9 </dev/urandom | head -c 12)
}

# Function to hash the password using SHA-256
hash_password() {
    echo -n "$1" | sha256sum | awk '{print $1}'
}

# Updated function to apply a Caesar cipher rotation to the hash
rotate_hash() {
    local hash="$1"
    local rotation=$(($RANDOM % 25 + 1))  # Rotation between 1 and 25

    # Create rotated alphabet for hexadecimal characters (0-9, a-f)
    HEX_ALPHABET="0123456789abcdef"
    ROTATED_HEX_ALPHABET=$(echo "$HEX_ALPHABET" | sed "s/^\(.\{$rotation\}\)\(.*\)/\2\1/")

    # Rotate the hash by replacing the original hexadecimal characters with the rotated ones
    echo "$hash" | tr "$HEX_ALPHABET" "$ROTATED_HEX_ALPHABET"
}

# Function to update the Samba password and store the rotated hash
update_samba_password() {
    # Generate a random password
    NEW_PASSWORD=$(generate_password)

    # Hash the random password
    HASHED_PASSWORD=$(hash_password "$NEW_PASSWORD")

    # Rotate the hash using Caesar cipher
    ROTATED_HASH=$(rotate_hash "$HASHED_PASSWORD")

    # Store the rotated hash in the trick.txt file
    echo "Rotated hash: $ROTATED_HASH"
    echo "$ROTATED_HASH" > "$TRICK_FILE"

    # Print the random password, hashed password, and rotated hash
    echo "Random password: $NEW_PASSWORD"
    echo "Hashed password (SHA-256): $HASHED_PASSWORD"
    echo "Rotated hash: $ROTATED_HASH"

    # Update the Samba password for the user (no prompt)
    (echo "$NEW_PASSWORD"; echo "$NEW_PASSWORD") | smbpasswd -s "$REAL_USER"

    echo "Updated Samba password for $REAL_USER"
}

# Function to rotate the password every 7 minutes
rotate_every_seven_minutes() {
    while true; do
        update_samba_password
        echo "Next password update in 7 minutes..."
        sleep 420  # Sleep for 7 minutes (420 seconds)
    done
}

# Remove existing [global] section and any duplicate share configurations
clean_samba_conf() {
    # Remove the [global] section and all its parameters
    echo "Removing existing [global] section..."
    sudo sed -i '/\[global\]/,/^\[/d' "$SAMBA_CONF"

    # Remove any duplicate [vulnerable_share] section
    if grep -q "\[vulnerable_share\]" "$SAMBA_CONF"; then
        echo "Removing duplicate [vulnerable_share] sections..."
        sudo sed -i '/\[vulnerable_share\]/,/^$/d' "$SAMBA_CONF"
    fi

    # Remove any duplicate [sensitive_information] section
    if grep -q "\[sensitive_information\]" "$SAMBA_CONF"; then
        echo "Removing duplicate [sensitive_information] sections..."
        sudo sed -i '/\[sensitive_information\]/,/^$/d' "$SAMBA_CONF"
    fi
}

# Add the new configuration to smb.conf
configure_samba_shares() {
    echo "Configuring Samba for two shares on random ports..."
    sudo bash -c "cat > $SAMBA_CONF" <<EOL
[global]
smb ports = $DECOY_PORT $REAL_PORT

[sensitive_information]
path = $DECOY_DIR
browseable = yes
writable = no
guest ok = yes

[vulnerable_share]
path = $REAL_DIR
browseable = yes
writable = yes
guest ok = no
valid users = $REAL_USER
EOL
}

# Backup the original Samba configuration if not already backed up
backup_samba_conf() {
    local backup_conf="/etc/samba/smb.conf.bak"
    if [ ! -f "$backup_conf" ]; then
        echo "Backing up the original Samba configuration to $backup_conf"
        sudo cp "$SAMBA_CONF" "$backup_conf"
    else
        echo "Backup of Samba configuration already exists."
    fi
}

# Configure UFW to allow the necessary ports
configure_ufw() {
    echo "Removing old UFW rules for previous SMB ports..."
    for rule in $(sudo ufw status | grep 'ALLOW' | grep 'tcp' | awk '{print $1}' | sort -u); do
        echo "Removing UFW rule for $rule"
        sudo ufw delete allow $rule
    done

    # Allow the new Samba ports
    echo "Allowing SMB traffic on ports $DECOY_PORT and $REAL_PORT..."
    sudo ufw allow "$DECOY_PORT/tcp"
    sudo ufw allow "$REAL_PORT/tcp"
    sudo ufw reload
}

# Start the Samba service
restart_samba_service() {
    echo "Restarting Samba service..."
    sudo systemctl restart smbd
    sudo systemctl restart nmbd
}

# Main function to set up everything and rotate the password
main() {
    backup_samba_conf
    clean_samba_conf
    configure_samba_shares
    configure_ufw
    restart_samba_service
    rotate_every_seven_minutes
}

# Run the main function
main
