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
	bash -c "sleep 7; curl --location --request POST 'http://host.docker.internal:5062/orks' --form 'orkName="$1"' --form 'orkUrl="$url"' --form 'signedOrkUrl="$sig"';" & 

else
	echo "Key exists: $Ed25519Key"
	echo $hash
	hash=$(tide-key pubhash $Ed25519Key) # Hash key pub, use as sudomain in local tunnel
fi

# Connect to tunnel server
localtunnel --subdomain $hash -s https://tunnel.tide.org --port 80 --no-dashboard http &
#localtunnel --subdomain $hash -s https://tunnel.tide.org --port 8443 --no-dashboard http

# Start ORK
priv=$(tide-key private-key $Ed25519Key)
dotnet H4x2-Node.dll $priv