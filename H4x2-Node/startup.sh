#!/bin/bash

Ed25519Key=$(cat /ork/priv/key.txt)

if [ -z "$Ed25519Key" ]; then # Checks if key exists
	echo "No Key Found... Generating one"
	# Generate key
	Ed25519Key=$(tide-key generate)
	echo $Ed25519Key >> /ork/priv/key.txt
	
	# Register ORK in Simulator
	hash=$(tide-key pubhash $Ed25519Key) # Hash key pub, use as sudomain in local tunnel
	url="https://$hash.tunnel.tide.org"
	echo "Using LocalTunnel URL: $url"
	sig=$(tide-key sign $Ed25519Key $url)

	# Wait for 7 seconds then submit rego. Simulator will check ORK endpoint for pub key
	bash -c "sleep 7; curl --location --request POST 'https://h4x22simulator.azurewebsites.net/orks' --form 'orkName="$1"' --form 'orkUrl="$url"' --form 'signedOrkUrl="$sig"';" & 

else
	echo "Key exists"
	hash=$(echo $RANDOM | md5sum | head -c 20; echo;)
	url="https://$hash.tunnel.tide.org"
	sig=$(tide-key sign $Ed25519Key $url)
	echo $url
	bash -c "sleep 7; curl --location --request POST 'https://h4x22simulator.azurewebsites.net/orks/update' --form 'orkName="$1"' --form 'newOrkUrl="$url"' --form 'signedOrkUrl="$sig"';" & 
fi

# Connect to tunnel server
#localtunnel --subdomain $hash -s https://tunnel.tide.org --port 80 --no-dashboard -c 1 http &
lt --port 80 --host https://tunnel.tide.org --subdomain $hash &

# Add cronjob to keep connection alive - request / every 10 min
{ crontab -l; echo "*/10 * * * * curl $url"; } | crontab -
crond

# Start ORK
priv=$(tide-key private-key $Ed25519Key)
dotnet H4x2-Node.dll $priv