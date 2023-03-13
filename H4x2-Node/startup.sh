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
	bash -c "sleep 7; curl -s --location --request POST 'https://new-simulator.australiaeast.cloudapp.azure.com/orks' --form 'orkName="$1"' --form 'orkUrl="$url"' --form 'signedOrkUrl="$sig"';" & 

else
	echo "Key exists"
	pub=$(tide-key public-key $Ed25519Key)
	exists=$(curl -s --get 'https://new-simulator.australiaeast.cloudapp.azure.com/orks/exists' --data-urlencode "pub=$pub")

	# Check if ork exists in simulator
	if [ "$exists" == "true" ]; then
		# Update ork url
		hash=$(echo $RANDOM | md5sum | head -c 20; echo;)
		url="https://$hash.tunnel.tide.org"
		sig=$(tide-key sign $Ed25519Key $url)
		echo $url
		bash -c "sleep 7; curl -s --location --request PUT 'https://new-simulator.australiaeast.cloudapp.azure.com/orks/update' --form 'newOrkName="$1"' --form 'newOrkUrl="$url"' --form 'signedOrkUrl="$sig"' --form 'orkPub="$pub"';" & 
	elif [ "$exists" == "false" ]; then
		# Register ork
		hash=$(tide-key pubhash $Ed25519Key) # Hash key pub, use as sudomain in local tunnel
		url="https://$hash.tunnel.tide.org"
		sig=$(tide-key sign $Ed25519Key $url)
		echo $url
		bash -c "sleep 7; curl -s --location --request POST 'https://new-simulator.australiaeast.cloudapp.azure.com/orks' --form 'orkName="$1"' --form 'orkUrl="$url"' --form 'signedOrkUrl="$sig"';" & 
	else
		echo "Network error - Could not reach simulator at https://new-simulator.australiaeast.cloudapp.azure.com/"

		exit 1
	fi
fi

# Connect to tunnel server
#localtunnel --subdomain $hash -s https://tunnel.tide.org --port 80 --no-dashboard -c 1 http &
lt --port 80 --host https://tunnel.tide.org --subdomain $hash &

# Start ORK
priv=$(tide-key private-key $Ed25519Key)
dotnet H4x2-Node.dll $priv &

sleep 60

# Function is put here to ensure container restarts once LT connection is lost
# 20 second timeout
active=$(curl -s -m 20 $url/active)
while  [ "$active" == "true" ]
do
  sleep 1200 # 20min
  active=$(curl -s -m 20 $url/active)
done # ORK has lost local tunnel connection, and will restart