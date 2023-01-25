# The Tide H4X.2 challenge - Zero Knowledge Authentication
The [H4X.2 challenge](http://h4x2.tide.org) is a showcase of the Tide Protocol's novel user authentication and digital protection technology, inviting the online community to learn, contribute and engage with Tide in the development of the protocol. It also encourages participants to identify and report security flaws, improvements or fixes via a bounty offer.

This challenge is the second series of the community-engagement program by the [Tide Foundation](https://tide.org) with a specific focus on Tide's next-generation technology: A new technology that grants access using keys **NOBODY** holds. Not even Tide! In this series, the challenge will change and evolve according to the community engagement, and will gradually introduce additional facets of the technology.

## Here we go with the 2nd Challenge!
Following the success of the 1st challenge...

## User Flow Diagram
![alt text](https://github.com/tide-foundation/Tide-h4x2/blob/main/diagrams/svg/H4x2_userflow.svg "Flow Diagram")

## Components
1. **H4x2-Node** - Minimal version of the Tide ORK, specific to this challenge.
1. **H4x2-TinySDK** - Minimal SDK for front-end website integration.
1. **H4x2-front** - Front-end website for this challenge.
    1. **Modules/H4x2-TideJS** - Tide Libraries including encryption + PRISM
1. **Diagrams** -  Diagrams for this challenge.
    1. [**H4x2_Challenge**](https://raw.githubusercontent.com/tide-foundation/Tide-h4x2/main/diagrams/svg/H4x2_Challenge.svg) - A technical diagram of the challenge.  
    2. [**H4x2_prism**](diagrams/svg/H4x2_prism.svg) - The mathematical diagram of Tide's PRISM. 
    3. [**H4x2_userflow**](https://github.com/tide-foundation/Tide-h4x2/blob/main/diagrams/svg/H4x2_userflow.svg) - A user flow diagram. 

# Installation
This guide aims to assist you in replicating the entire challenge environment locally - so you can run it yourself freely.

While all the components of the environment are cross-platform, this manual describes how to set it up in a Windows environment. Similar steps can be followed to achieve the same on Linux.

There is also a [video](https://vimeo.com/780973408/d5df625214) to help you with the installation steps.

## Prerequisite

The following components are required to be set up ahead of the deployment:
1. [.NET 6 Build apps - SDK](https://dotnet.microsoft.com/en-us/download/dotnet/6.0 ".net Core 6 Download") Only if setting up local environment
2. Clone Repository (`git clone https://github.com/tide-foundation/Tide-h4x2-2/`)
3. [Install docker](https://www.docker.com/ "Docker download") If you want to run your own ORK in the Tide Network

## Running your own ORK
This will be for people looking to join the Tide Network and run an ORK themselves. They can request Tide to create a Prize account on their ORKs to give them an opportunity to try and crack the account.
### Set up docker environment
```
docker pull tidethebes/h4x2-ork:latest
docker volume create ork-volume
```
This will pull the ORK image from the docker image registry then create a docker volume. We use docker volumes so that ORKs can have persistant storage (e.g. storing their local DBs or keys).
### Run your docker ORK
```
docker run --rm -d --name ork \
  --mount source=ork-volume,target=/ork \
  tidethebes/h4x2-ork:latest <your ork name>
```
Your ork name is used so that you or someone else can identify your ORK when they do the account sign up process. (You could identify it with the URL but having an ORK name is more fun).

***Note: Ork name can be max 20 characters long. No spaces***
## Setting up your own local environment
This will be for people who wish to set up a local vendor, local simulator, and local ORK. For hackers wanting to better understand the system.
### Run the Vendor
Directory at: Tide-h4x2-2\H4x2-Vendor\H4x2-Vendor

Firstly, change the simulator URL in appsettings.json from this
```
"Api": "https://h4x22simulator.azurewebsites.net"
```
To this:
```
"Api": "http://localhost:5062"
```
Then run the vendor:
```
dotnet run --urls=http://localhost:5231
```
### Run the Simulator
```
cd Tide-h4x2-2\H4x2-Simulator\H4x2-Simulator
dotnet run --urls=http://localhost:5062
```
### Run the Ork
Directory at: Tide-h4x2-2\H4x2-Node\H4x2-Node

Firstly, change the simulator URL and local database location in appsettings.json from this
```
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*",
  "Urls": "http://+:80",
  "ConnectionStrings": {
    "LocalDbConnectionString": "Data Source=/ork/db/LocalDatabase.db"
  },
  "Endpoints": {
    "Simulator": {
      "Api": "https://h4x22simulator.azurewebsites.net"
    }
  }
}
```
To this:
```
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*",
  "Urls": "http://+:80",
  "ConnectionStrings": {
    "LocalDbConnectionString": "Data Source=LocalDatabase.db"
  },
  "Endpoints": {
    "Simulator": {
      "Api": "http://localhost:5062"
    }
  }
}
```
Then change the default (public) vendor URL in the Tide Enclave (signin.js @ line 93) from:
```
vendorUrl: "https://h4x22vendor.azurewebsites.net"
```
To:
```
vendorUrl: "http://localhost:5231"
```

Since we aren't using the docker image which does the ork registration process automatically, we'll have to do it manually. Make sure you have a tool like Postman or curl with you.

Firstly we'll need to generate a key using the Tide-Key tool. Install it with:
```
dotnet tool install --global Tide-Key
```
Now to do the ork registration process manually
```
tide-key generate                        <- Store the output, call it "secret"
tide-key private-key <secret>            <- Store the output, call it "private key"
tide-key sign <secret> http://localhost  <- Store the output, call it "signature"
```
Now let's run the ORK (we need to do this before the registration because the simulator will query the ORK public via the ORK's URL).
```
dotnet run <secret>
```

Now let's submit the registration to the simulator:
```
curl --location --request POST 'http://localhost:5062/orks' \
--form 'orkUrl="http://localhost"' \
--form 'signedOrkUrl="<signature>"' \
--form 'orkName="myLocalOrk"'
```

Hopefully, you should see a returned message of "{"message":"Ork created"}". This means the simulator has registered the ORK.
### Testing the local environment
Navigate to http://localhost where you should see a Sign In/Up page. Start testing the available functions! 

As always, the Debug Page will be available at http://localhost/modules/H4x2-TideJS/test.html for those who wish to see how we can achieve the sign up/in processes without a UI.

Keep in mind the only ORK available for selection will be yours, since you are using a local simulator.


## Special Case - Run your own ORK WITHOUT using our localtunnel server (You will need a public URL)
This is for people who don't trust our local tunnel servers, want to use their own URL, or just like network speed.

Directory at: Tide-h4x2-2\H4x2-Node\H4x2-Node

Since we aren't using the docker image which does the ork registration process automatically, we'll have to do it manually. Make sure you have a tool like Postman or curl with you.

Firstly we'll need to generate a key using the Tide-Key tool. Install it with:
```
dotnet tool install --global Tide-Key
```
Now to do the ork registration process manually
```
tide-key generate                         <- Store the output, call it "secret"
tide-key private-key <secret>             <- Store the output, call it "private key"
tide-key sign <secret> <your public URL>  <- Store the output, call it "signature"
```
To generate SSL certs, use a tool like https://certbot.eff.org/ as its free and its what I'll be using for the example.

Now that you've got your SSL certs as files called "fullchain.pem" and "privkey.pem", we can begin setting up the ORK. Firsly add these configs in appsettings.json:
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
Now let's run the ORK (we need to do this before the registration because the simulator will query the ORK public via the ORK's URL).
```
dotnet run <secret>
```

Now let's submit the registration to the simulator:
```
curl --location --request POST 'https://h4x22simulator.azurewebsites.net' \
--form 'orkUrl="<your public url>"' \
--form 'signedOrkUrl="<signature>"' \
--form 'orkName="<your ork name>"'
```

Hopefully, you should see a returned message of "{"message":"Ork created"}". You ORK is now registered to the Tide Network without our localtunnel server.

## A Note About SSL
We don't use it because we want to secure our communications. The Tide Protocol already does that. The only reason we use it is so we can access the native JS crypto libraries which are only available under an SSL connection. If it weren't for that we'd be using HTTP.

## Troubleshooting
Ask for any help in the Discord channel! The community and our devs are there for you.

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
[^ork]: Tide's decentralized network is made of many nodes named ORKs, which stands for Orchestrated Recluder of Keys. A single ORK operates more like a drone in a hive than a node in a network as it performs work that's unique to it and is vastly different than other ORKs. That work is entirely incomprehensive by itself, even to itself. Meaning, the network perform a process where each ORK performs part of that process without knowing or understanding anything about the process itself. Only after the ORKs complete their parts (which is done in parallel), the network produces a meaningful result. This "incomprehensible partial processing", or as we call it "Blind Secret Processing" is done using Tide's groundbreaking new Threshold Cryptography done in Multi-Party Computation.
[^key]: Tide's specific 'key point' is a representation of a cryptographic key as a geometric point on an Edward25519 Elliptic Curve.
