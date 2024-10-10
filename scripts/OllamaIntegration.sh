#!/bin/bash
# Wazuh - YARA active response with Ollama integration
# Copyright (C) 2015-2024, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

#------------------------- Configuration -------------------------#

# Ollama API endpoint
OLLAMA_API="http://127.0.0.1:11434/api/chat"
OLLAMA_MODEL="llama3.2:latest"

# Set LOG_FILE path
LOG_FILE="logs/active-responses.log"

#------------------------- Gather parameters -------------------------#

# Extra arguments
read INPUT_JSON
YARA_PATH=$(echo $INPUT_JSON | jq -r .parameters.extra_args[1])
YARA_RULES=$(echo $INPUT_JSON | jq -r .parameters.extra_args[3])
FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.syscheck.path)

size=0
actual_size=$(stat -c %s ${FILENAME})
while [ ${size} -ne ${actual_size} ]; do
    sleep 1
    size=${actual_size}
    actual_size=$(stat -c %s ${FILENAME})
done

#----------------------- Analyze parameters -----------------------#

if [[ ! $YARA_PATH ]] || [[ ! $YARA_RULES ]]
then
    echo "wazuh-YARA: ERROR - YARA active response error. YARA path and rules parameters are mandatory." >> ${LOG_FILE}
    exit 1
fi

#------------------------- Main workflow --------------------------#

# Execute YARA scan on the specified filename
YARA_output="$("${YARA_PATH}"/yara -w -r -m "$YARA_RULES" "$FILENAME")"

if [[ $YARA_output != "" ]]
then
    # Attempt to delete the file if any YARA rule matches
    if rm -rf "$FILENAME"; then
        echo "wazuh-YARA: INFO - Successfully deleted $FILENAME" >> ${LOG_FILE}
    else
        echo "wazuh-YARA: INFO - Unable to delete $FILENAME" >> ${LOG_FILE}
    fi

    # Flag to check if Ollama API is unreachable
    ollama_api_unreachable=false

    # Iterate every detected rule
    while read -r line; do
        # Extract the description from the line using regex
        description=$(echo "$line" | grep -oP '(?<=description=").*?(?=")')
        if [[ $description != "" ]]; then
            # Prepare the message payload for Ollama
            payload=$(jq -n \
                --arg model "$OLLAMA_MODEL" \
                --arg desc "$description" \
                '{
                    model: $model,
                    messages: [
                        {
                            role: "user",
                            content: "In one paragraph, tell me about the impact and how to mitigate \($desc)"
                        }
                    ],
                    stream: false
                }')

            # Query Ollama for more information
            ollama_response=$(curl -s -X POST "$OLLAMA_API" \
                -H "Content-Type: application/json" \
                -d "$payload")

            # Check for Ollama API connection error
            if [ $? -ne 0 ]; then
                ollama_api_unreachable=true
                echo "wazuh-YARA: ERROR - Unable to reach Ollama API" >> ${LOG_FILE}
                # Log Yara scan result without Ollama response
                echo "wazuh-YARA: INFO - Scan result: $line | ollama_response: none" >> ${LOG_FILE}
            else
                # Extract the response text from Ollama API response
                response_text=$(echo "$ollama_response" | jq -r '.message.content')

                # Check if the response text is null and handle the error
                if [[ $response_text == "null" ]]; then
                    echo "wazuh-YARA: ERROR - Ollama API returned null response: $ollama_response" >> ${LOG_FILE}
                else
                    # Combine the YARA scan output and Ollama response
                    combined_output="wazuh-YARA: INFO - Scan result: $line | ollama_response: $response_text"

                    # Append the combined output to the log file
                    echo "$combined_output" >> ${LOG_FILE}
                fi
            fi
        else
            echo "wazuh-YARA: INFO - Scan result: $line" >> ${LOG_FILE}
        fi
    done <<< "$YARA_output"

    # If Ollama API was unreachable, log a specific message
    if $ollama_api_unreachable; then
        echo "wazuh-YARA: INFO - Ollama API is unreachable. Ollama response omitted." >> ${LOG_FILE}
    fi
else
    echo "wazuh-YARA: INFO - No YARA rule matched." >> ${LOG_FILE}
fi

exit 0;