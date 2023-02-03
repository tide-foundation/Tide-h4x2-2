# The Tide H4X.2 challenge - Decentralized Zero-Knowledge Authentication
The [H4X.2 challenge](http://h4x2.tide.org) is a showcase of the Tide Protocol's novel user authentication and digital protection technology, inviting the online community to learn, contribute and engage with Tide in the development of the protocol. It also encourages participants to identify and report security flaws, improvements or fixes via a bounty offer.

This challenge is the second series of the community-engagement program by the [Tide Foundation](https://tide.org) with a specific focus on Tide's next-generation technology: A new technology that grants access using **keys NO ONE will ever hold**. Not even Tide! In this series, the challenge will change and evolve according to the community engagement, and will gradually introduce additional facets of the technology.

## Here we go with the 2nd Challenge!
Following the success of the [1st challenge](https://github.com/tide-foundation/Tide-h4x2) the second challenge is a bit more interesting but with an identical high-level concept: A secret code is hidden and is only unlocked when the correct username and password are entered.  The first one to post the secret code on Tide's [#h4x](https://discord.com/channels/968760660659953714/1042098770885738526) channel on its Discord server - wins!  The password authentication process is obfuscated and decentralized using Tide's [PRISM](/diagrams/svg/H4x2_prism.svg) cryptography - the world's most secure password authentication[^pwd].  In this challenge, participants need to follow the opt-in instructions on the Discord [#h4x](https://discord.com/channels/968760660659953714/1042098770885738526) channel to participate. Once opted-in, each participant will be assigned a unique account with its own unique username, password and secret that uses 3 ORKs[^ork]. Participants will need to use their username and guess (or crack) their password, in order to decipher their secret and win. Now here's where it gets interesting: participants may host 1 or even 2 of those ORKs and gain full access to it, to help them crack their secret.  The entire source code for the challenge, together with full documentation, is offered herewith for those wishing to take a deeper look.

## Terminology

Below are terms that are important to understand within the context of the Tide Protocol and this challenge.

**Vendor** - Any consumer-facing website that manages and stores all the secrets for all the accounts. In this instance, the landing page [here](https://h4x2.tide.org).

**Enclave** - A Tide secure web interface hosted on each and every ORK.  A user can pick whichever enclave they want.  

**Consumer** - Any individual natural person that has a uniquely identified representation or data footprint (usually in the form of a user account or identity) in a Vendor’s database. A participant in this case!

**BC Simulator** - A component that simulates the network's Blockchain component. 

**ORK (Orchestrated Recluder of Keys)**[^ork] -  A node in the Tide Protocol decentralized network. 

**CVK** - Consumer Vendor Key.  A key pair for each user. 

**LT Client/Server** - An optional tunnel service that allows participants to easily host an ORK at home without the need to mess around with public IP addresses, DNS entries, custom URL's, SSL certificates, IP forwarding and router/firewall/reverse-proxy settings.

## Component Diagram
![alt text](https://raw.githubusercontent.com/tide-foundation/Tide-h4x2-2/main/diagrams/svg/H4x2_CompDiagram.svg "Component Diagram")
## User Flow Diagram
![alt text](/diagrams/svg/H4x2_userflow.svg "Signup Flow Diagram")

## Components
1. **H4x2-Node** - Minimal version of the Tide ORK, specific to this challenge.  While Tide will host 5 nodes, anyone will have an option to host their own nodes as well.  
1. **H4x2-Simulator** - Simulates the Blockchain element.  
1. **H4x2-Vendor** - A landing page for the challenge.  This also represents a platform vendor that will integrate Tide. 
1. **H4x2-TinySDK** - Minimal SDK for front-end website integration.
1. **Diagrams** -  Diagrams for this challenge.
    1. [**H4x2_CompDiagram**](https://raw.githubusercontent.com/tide-foundation/Tide-h4x2-2/main/diagrams/svg/H4x2_CompDiagram.svg) - Component Diagram.  
    2. [**H4x2_prism**](/diagrams/svg/H4x2_prism.svg) - The mathematical diagram of Tide's PRISM authentication. 
    3. [**H4x2_userflow**](https://raw.githubusercontent.com/tide-foundation/Tide-h4x2-2/main/diagrams/svg/H4x2_userflow.svg) - User flow diagram. 
    4. [**H4x2_signup**](https://raw.githubusercontent.com/tide-foundation/Tide-h4x2-2/main/diagrams/svg/H4x2_signup.svg) - Sign-up flow diagram. 
    5. [**H4x2_signin**](https://raw.githubusercontent.com/tide-foundation/Tide-h4x2-2/main/diagrams/svg/H4x2_signin.svg) - Sign-in flow diagram. 
# Installation
This guide aims to assist you in replicating the entire challenge environment locally - so you can run it yourself freely.

While all the components of the environment are cross-platform, this manual describes how to set it up in a Windows environment. Similar steps can be followed to achieve the same on other OS.

Here's the list of videos to help with installation: 
1. [Challenge 1.0 Recap](https://vimeo.com/794714191) - A recap of the previous challenge.
1. [Challenge 2.0 Overview](https://vimeo.com/794714239) - A quick overview of the challenge.
1. [Local Setup](https://vimeo.com/794714266) - Running the challenge in your local environment. 
1. [Running an ORK Node](https://vimeo.com/794763943) - Hosting your own ORK. 
## Prerequisite

The following components are required to be set up ahead of the deployment:
1. [.NET 6 Build apps - SDK](https://dotnet.microsoft.com/en-us/download/dotnet/6.0 ".net Core 6 Download") (Only if setting up local environment)
2. Clone repository: `git clone https://github.com/tide-foundation/Tide-h4x2-2.git`
3. [Docker](https://www.docker.com/ "Docker download") - If you want to host your own ORK in the Tide Network

## Hosting your own ORK
This will be for challenge participants looking to join the Tide Network and run an ORK themselves. This will allow you to request Tide to create an account on your ORKs and give you an opportunity to hack your own account.
### Run your ORK docker
Please watch [this video](https://vimeo.com/794763943) on crucial details about the ORK.
Then download, install and run the ORK docker image with this PowerShell/CMD command:
```
docker run --rm -d --name ork --mount source=ork-volume,target=/ork tidethebes/h4x2-ork <your ork name>
```
<sup>(Obviously, replace <your ORK name> with the name you chose for your node. ***Note: Ork name can be max 20 characters long. No spaces!***)</sup>
</p>
Your ORK name is used so you, or anyone, can identify your ORK during the account sign up process.

If you want to create an ORK image using your own code, make sure to:
1. Change line 32 in [Program.cs](/H4x2-Node/H4x2-Node/Program.cs#L32) to:
```
 var key = new Key(BigInteger.Parse(args[0]));
```
2. Change the LocalDB location in [appsettings.json](/H4x2-Node/H4x2-Node/appsettings.json#L11) to `"Data Source='/ork/db/LocalDatabase.db'"`.
3. Build image with this command (there are different Dockerfiles):
```
docker build -f H4x2-Node/Dockerfile_Custom -t myOrkImage .
```

## Setting up your own local environment
This will be for those who wish to set up an entire environment including a local vendor, local simulator, and local ORKs. I.e. Hackers wanting to better understand the system.
### Run the Vendor
Directory at: Tide-h4x2-2\H4x2-Vendor\H4x2-Vendor

Firstly, change the Blockchain Simulator URL in [appsettings.json](/H4x2-Vendor/H4x2-Vendor/appsettings.json#L15):
```
"Api": "http://localhost:5062"
```
Then run the vendor:
```
dotnet run --urls=http://localhost:5231
```
### Run the Blockchain Simulator
Run the simulator:
```
cd Tide-h4x2-2\H4x2-Simulator\H4x2-Simulator
dotnet run --urls=http://localhost:5062
```
### Run the Ork
Directory at: Tide-h4x2-2\H4x2-Node\H4x2-Node

Firstly, change the BC Simulator's URL in [appsettings.json](/H4x2-Node/H4x2-Node/appsettings.json#L15):
```
"Api": "http://localhost:5062"
```
Then change the default (public) vendor's and simulator's URLs in the Tide Enclave code at [signin.js](/H4x2-Node/H4x2-Node/wwwroot/js/signin.js#L84) to:
```
simulatorUrl: 'http://localhost:5062/',
vendorUrl: 'http://localhost:5231/'
```
And also change the default (public) vendor's and simulator's URLs in the main.js [here](/H4x2-Node/H4x2-Node/wwwroot/js/main.js#L110):

```
urls: ["http://localhost:5062"],
```
And [here](/H4x2-Node/H4x2-Node/wwwroot/js/main.js#L135):
```
simulatorUrl: 'http://localhost:5062/',
vendorUrl: 'http://localhost:5231/'
```

Since we aren't using the docker image which does the ORK registration process automatically, we'll have to do it manually. Make sure you have a tool like [Postman](https://www.postman.com/downloads/) or [curl](https://curl.se/) available.

Firstly, we'll need to generate a key using the Tide-Key tool. Install it with:
```
dotnet tool install --global Tide-Key
```
Perform the ORK registration process manually:
```
tide-key generate                        <- Assume <secret> is the output
tide-key private-key <secret>            <- Assume <private key> is the output
tide-key sign <secret> http://localhost  <- Assume <signature> is the output
```
Run the ORK (we need to do this before the registration because the simulator will query the ORK's public key via the ORK's URL).
```
set TIDE_KEY=<private key>
dotnet run
```

Submit the registration to the simulator:
```
curl --location --request POST 'http://localhost:5062/orks' \
--form 'orkUrl="http://localhost"' \
--form 'signedOrkUrl="<signature>"' \
--form 'orkName="myLocalOrk"'
```

Hopefully, you should see a returned message of `{"message":"Ork created"}`. This means the simulator has registered the ORK.
### Testing the local environment
Navigate to http://localhost where you should see a Sign In/Sign Up page. Start testing the available functions! 

As always, the Debug Page will be available at http://localhost/modules/H4x2-TideJS/test.html for those who wish to see how we can achieve the sign up/sign in processes without a UI.

Keep in mind the only ORK available for selection will be yours, since you are using a local simulator.


## Special Case - Running your own ORK on your own domain
This is for people who don't trust our HTTP tunneling servers, want to use their own URL, or just want better network performance.

### Prerequisits
To run your own ORK under your domain, you'll need:
1. Static / Dynamic IP address for the ORK
1. Custom DNS entry
1. SSL certificate for that domain
1. Knowledge on how to set up a publically available server

### Set up

Directory at: Tide-h4x2-2\H4x2-Node\H4x2-Node

Since we aren't using the docker image which does the ORK registration process automatically, we'll have to do it manually. Make sure you have a tool like [Postman](https://www.postman.com/downloads/) or [curl](https://curl.se/) available.

Firstly we'll need to generate a key using the Tide-Key tool. Install it with:
```
dotnet tool install --global Tide-Key
```
Perform the ORK registration process manually:
```
tide-key generate                        <- Assume <secret> is the output
tide-key private-key <secret>            <- Assume <private key> is the output
tide-key sign <secret> http://localhost  <- Assume <signature> is the output
```
To generate SSL certs, use a tool like https://certbot.eff.org/ as its free and its what I'll be using it for this example.

Assuming that you've got your SSL certs as "fullchain.pem" and "privkey.pem" files, we can begin setting up the ORK. Firsly, add this config inside (before the last curly bracket!) [appsettings.json](/H4x2-Node/H4x2-Node/appsettings.json):
```
"Kestrel": {
    "EndPoints": {
      "HttpsDefaultCert": {
        "Url": "https://*:443"
      },
      "Http": {
        "Url": "http://*:80"
      }
    },
    "Certificates": {
      "Default": {
        "Path": "<path to key>/fullchain.pem",
        "KeyPath": "<path to key>/privkey.pem"
      }
    }
  }
```
Run the ORK (we need to do this before the registration because the BC Simulator will query the ORK's public key via the ORK's URL):
```
dotnet run <secret>
```

Submit the registration to the BC Simulator:
```
curl --location --request POST 'https://h4x22simulator.azurewebsites.net' \
--form 'orkUrl="<your public url>"' \
--form 'signedOrkUrl="<signature>"' \
--form 'orkName="<your ork name>"'
```

You should see a returned message of `{"message":"Ork created"}`. You ORK is now registered to the Tide Network, bypassing the HTTP tunnelling server and you should be able to access it using <your public url>.

## A Note About SSL
For the purpose of these challenges, we attempt using SSL as little as possible. We don't need SSL to secure anything. The Tide Protocol already does that. The only reason SSL is used here is because the native JavaScript cryptographic functions are only available under an SSL connection. If it weren't for that we'd be using HTTP to give you as much hacking advantage as possible.

## Troubleshooting
Ask for any help in the [Discord server!](https://discord.com/channels/968760660659953714/1042098770885738526) The community and our devs are there for you.

## A Quick Note on the Throttling
You may notice that regardless if you entered the right password or not, the ORKs will throttle you after few attempts. This is due to the fact that it is virtually IMPOSSIBLE (unless you break Eliptic Curve cryptography) for the ORKs to determine what password the user is trying and whether its correct or not (specifically, in this challenge). All the ORKs do is apply their partial PRISM value to a point. Therefore, since the ORKs have no idea what the password is and since the user is obfuscating their password point with a random number, it guarantees that the ORKs 'authenticate' the user without any knowledge of their password. Cool, right?

# More info
[The Tide Website](https://tide.org)

## Get in touch!

[Tide Discord](https://discord.gg/42UCeW4smw)

[Tide Twitter](https://twitter.com/tidefoundation)

  <a href="https://tide.org/licenses_tcoc2-0-0-en">
    <img src="https://img.shields.io/badge/license-TCOC-green.svg" alt="license">
  </a>
</p>

[^pwd]: Tide's focus on developing the world's most secure online password authentication mechanism is because passwords still, unfortunately, are the most common online authentication mechanism used. In general, password authentication is a significantly inferior mechanism compared to its many alternatives. Most of the alternatives (e.g. MFA, passwordless, FIDO2, etc) also suffer from security risks which Tide's authentication helps alleviate. Tide's superior password protection mechanism isn't intended to discourage users from switching to a better alternative, instead offers a better interim-measure until such inevitable switch occurs.
[^ork]: Tide's decentralized network is made of many nodes named ORKs, which stands for Orchestrated Recluder of Keys. A single ORK operates more like a drone in a hive than a node in a network as it performs work that's unique to it and is vastly different than other ORKs. That work is entirely incomprehensible by itself, even to itself. Meaning, the network perform a process where each ORK performs part of that process without knowing or understanding anything about the process itself. Only after the ORKs complete their parts (which is done in parallel), the network produces a meaningful result. This "incomprehensible partial processing", or as we call it "Blind Secret Processing" is done using Tide's groundbreaking new Threshold Cryptography done in Multi-Party Computation.
[^key]: Tide's specific 'key point' is a representation of a cryptographic key as a geometric point on an Edward25519 Elliptic Curve.
