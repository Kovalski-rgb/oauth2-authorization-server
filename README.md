# oauth2-authorization-code-flow
Atividade de OAuth do Bradesco

## Before running:

You'll need to set your client_id for both google and facebook APIS inside `main.mjs`, of the first 2 lines

## How to run?

```
git clone https://github.com/Kovalski-rgb/oauth2-authorization-server.git
cd oauth2-authorization-server
npm install
node main.mjs
```

Your server will be running on port 8080

Here are the currently available endpoints:

```
GET /oauth/codeChallenge
    description:
        Gets a random Challenge_Verifier, the type needs to be specified on the body of the request, default is Plain
    body:
        "challenge_type"
            "sha256" for Challenge_Code as sha_256

GET /google/login
    description:
        Redirects the user to a google auth page, returns the id_token and state

POST /google/login
    description:
        Gets basic user information from the google API, creates a new user inside the mock database and returns an access-token
    body:
        id_token: the id_token from the OIDC exchange
        state: the state of the exchange

GET /google/user-info
    description:
        Gets registered user info from the mock-database, only accessible via a valid access-token
    header:
        Authorization: Bearer [your access-token]

GET /facebook/login
    description:
        Redirects the user to a facebook auth page, returns the id_token and state

POST /facebook/login
    description:
        Gets basic user information from the facebook API, creates a new user inside the mock database and returns an access-token
    body:
        id_token: the id_token from the OIDC exchange
        state: the state of the exchange

GET /facebook/user-info
    description:
        Gets registered user info from the mock-database, only accessible via a valid access-token
    header:
        Authorization: Bearer [your access-token]
```
