# wazuh-response-scripts

This repository contains my custom active response scripts for the Wazuh agent.

## Install

**First inspect and edit scripts/OllamaIntegration.sh to set the Ollama API endpoint and model.**

Set permissions to execute the script as root:

```bash
chmod +x install.sh
sudo ./install.sh
```

## Scripts

### OllamaIntegration.sh

This script integrates with the Wazuh agent to provide real-time file scanning using YARA rules and Ollama using Llama3.2 for additional analysis.
