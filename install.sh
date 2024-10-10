#!/bin/bash

# Copy scripts from scripts directory to /var/ossec/active-response/bin/
if [ -d "/var/ossec/active-response/bin/" ]; then
    echo "Copying scripts to /var/ossec/active-response/bin/"
    cp scripts/* /var/ossec/active-response/bin/
    
    # Change permissions for each script
    for script in /var/ossec/active-response/bin/*.sh; do
        sudo chown root:wazuh "$script"
        sudo chmod 750 "$script"
        echo "Set permissions for $script"
    done
else
    echo "Error: /var/ossec/active-response/bin/ directory not found"
    exit 1
fi

# Prompt user for directories to monitor
echo "Enter directories to monitor (space-separated, press Enter when done):"
read -r directories

# Default to /home if no input
if [ -z "$directories" ]; then
    directories="/home"
fi

# Update Wazuh agent configuration
config_file="/var/ossec/etc/ossec.conf"
if [ -f "$config_file" ]; then
    # Check if <syscheck> block exists
    if grep -q "<syscheck>" "$config_file"; then
        # Add directories to monitor within <syscheck> block
        sudo sed -i "/<syscheck>/a\\$(printf '  <directories realtime="yes">%s</directories>\n' $directories)" "$config_file"
        echo "Updated $config_file with directories to monitor"
    else
        echo "Error: <syscheck> block not found in $config_file"
    fi
else
    echo "Error: $config_file not found"
fi

# Restart Wazuh agent
echo "Restarting Wazuh agent..."
sudo systemctl restart wazuh-agent

echo "Installation complete"