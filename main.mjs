const FACEBOOK_CLIENT_ID = '';
const GOOGLE_CLIENT_ID = '';

import crypto from "crypto";
import express from "express";
import bodyParser from "body-parser";
import { Issuer, generators } from 'openid-client';

const sha256 = (input) => crypto.createHash('sha256').update(input);

// Configurações
const FACEBOOK_REDIRECT_URL = 'https://oidcdebugger.com/debug';

// Facebook OIDC Client
const facebookIssuer = await Issuer.discover('https://www.facebook.com');
const facebookClient = new facebookIssuer.Client({
    client_id: FACEBOOK_CLIENT_ID,
    redirect_uris: [FACEBOOK_REDIRECT_URL],
    response_types: ['id_token'],
});


// Configurações do EXPRESS
const app = express();
const port = 8080;

app.use(bodyParser.json());     // to support JSON-encoded bodies
app.use(bodyParser.urlencoded({ // to support URL-encoded bodies
  extended: true
}));

// Mock de um banco de dados
const DATABASE_FB = {
    // Tabela NONCES
    nonces: {},

    // Tabela USERS
    users: {},

    // Tabela SESSIONS
    sessions: {},
};

app.get('/facebook/login', async (req, res) => {
    // Cria um um state e um nonce aleatórios
    const state = generators.state();
    const nonce = generators.nonce();

    // Armazena o state e o nonce no banco de dados
    DATABASE_FB.nonces[state] = {
        nonce,
        expires_at: Date.now() + (15 * 60 * 1000), // expira em 15 minutos
    };

    // Cria uma URL de autorização para o facebook
    const authorizationUrl = facebookClient.authorizationUrl({
        scope: 'openid',
        state: state,
        response_mode: 'fragment',
        nonce,
    });

    // Redireciona o usuário para a URL de autorização criada acima
    res.redirect(authorizationUrl);
});

app.post('/facebook/login', async (req, res) => {
    const { state, id_token } = req.body;

    // Valida se o id_token foi fornecido
    if (!id_token) {
        res.status(412).json({ error: 'id_token is required' });
        return;
    }

    // Valida se o state fornecido é valido
    if (!state || !DATABASE_FB.nonces[state]) {
        res.status(400).json({ error: 'Invalid state' });
        return;
    }

    // Verifica se o state expirou
    const { nonce, expires_at } = DATABASE_FB.nonces[state];
    if (Date.now() >= expires_at) {
        // Apaga o state do banco de dados
        delete DATABASE_FB.nonces[state];
       
        // Retorna um erro
        res.status(400).json({ error: 'this state has expired' });
        return;
    }

    let tokenSet;
    try {
        // Valida se o ID_TOKEN e o NONCE são válidos
        tokenSet = await facebookClient.callback(
            FACEBOOK_REDIRECT_URL,
            { id_token },
            { nonce }
        );
    } catch(error) {
        // Se o ID_TOKEN for inválido, retorne um erro
        res.status(400).json({ error: JSON.stringify(error) });
        return;
    }

    // Le as informações do ID_TOKEN
    const { sub, email } = tokenSet.claims();
    
    // Verifica se o usuário já esta cadastrado no banco de dados
    const user_id = `facebook-${sub}`;
    if (!DATABASE_FB.users[user_id]) {
        // Se não estiver, cadastra dele no banco de dados
        DATABASE_FB.users[user_id] = {
            id: user_id,
            email,
            created_at: Date.now(),
        };
    }

    // Cria um access_token opaco para o usuário logado
    const access_token = generators.random();
    const access_token_expires_at = Date.now() + (24 * 60 * 60 * 1000); // expira em 24 horas

    // Armazena o access_token no banco de dados
    DATABASE_FB.sessions[access_token] = {
        user_id: user_id,
        expires_at: access_token_expires_at,
    };

    // Retorna o access_token para o usuário logado
    res.status(200).json({
        access_token,
        expires_at: access_token_expires_at,
        token_type: 'Bearer'
    });
});

// Middleware que verifica o access_token
const authenticationMiddleware = (req, res, next) => {
    const { authorization } = req.headers; // Recupera o header Authorization

    if (!authorization) {
        res.status(401).json({ error: 'unauthorized, no header present' });
        return;
    }

    // remove o prefixo 'Bearer '
    let access_token = null;
    if (authorization.startsWith('Bearer ')) {
        access_token = authorization.substr(7);
    } else {
        access_token = authorization;
    }

    // Verifica se a sessão existe no banco de dados
    const sessionFB = DATABASE_FB.sessions[access_token];
    const sessionGL = DATABASE_GL.sessions[access_token];
    if (!sessionFB && !sessionGL) {
        res.status(401).json({ error: 'unauthorized' });
        return;
    }

    // Verifica se alguma das sessões expiraramv
    if (sessionFB && Date.now() >= sessionFB.expires_at) {
        // Deleta a sessão do banco de dados
        delete DATABASE_FB.sessions[access_token];
        res.status(401).json({ error: 'facebook session expired' });
        return;
    }
    if (sessionGL && Date.now() >= sessionGL.expires_at) {
        // Deleta a sessão do banco de dados
        delete DATABASE_GL.sessions[access_token];
        res.status(401).json({ error: 'google session expired' });
        return;
    }

    // Armazena as informações da sessão na requisição
    req.session = sessionFB ? sessionFB : sessionGL;
    next();
};

// Exemplo de endpoint protegido
app.get('/facebook/user-info', authenticationMiddleware, async (req, res) => {
    const { session } = req;

    // Le o id do usuário logado
    const { user_id } = session;

    // Le as informações do usuário do banco de dados
    const user = DATABASE_FB.users[user_id];

    // Retorna as informações do usuário
    if(user){
        res.status(200).json(user)
    }else{
        res.status(200).json("User did not log in with its facebook account");
    }
});

// Exemplo de endpoint protegido
app.get('/google/user-info', authenticationMiddleware, async (req, res) => {
    const { session } = req;

    // Le o id do usuário logado
    const { user_id } = session;

    // Le as informações do usuário do banco de dados
    const user = DATABASE_GL.users[user_id];

    // Retorna as informações do usuário
    if(user){
        res.status(200).json(user)
    }else{
        res.status(200).json("User did not log in with its google account");
    }
});

// ------------------ API da GOOGLE!

const GOOGLE_REDIRECT_URL = 'https://oidcdebugger.com/debug';

// Mock de um banco de dados
const DATABASE_GL = {
    // Tabela NONCES
    nonces: {},

    // Tabela USERS
    users: {},

    // Tabela SESSIONS
    sessions: {},
};

// Google OIDC Client
const googleIssuer = await Issuer.discover('https://accounts.google.com');
const googleClient = new googleIssuer.Client({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uris: [GOOGLE_REDIRECT_URL],
    response_types: ['id_token'],
});

app.get('/google/login', async (req, res) => {
    // Cria um um state e um nonce aleatórios
    const state = generators.state();
    const nonce = generators.nonce();

    // Armazena o state e o nonce no banco de dados
    DATABASE_GL.nonces[state] = {
        nonce
    };

    const authorizationUrl = googleClient.authorizationUrl({
        scope: 'openid profile',
        state: state,
        response_mode: 'fragment',
        nonce,
    });

    // Redireciona o usuário para a URL de autorização criada acima
    res.redirect(authorizationUrl);
});


app.post('/google/login', async (req, res) => {
    const { state, id_token } = req.body;
    
    if (!id_token) {
        res.status(400).json({ error: 'id_token is required' });
        return;
    }

    if (!state || !DATABASE_GL.nonces[state]) {
        res.status(400).json({ error: 'Invalid state' });
        return;
    }

    const { nonce, expires_at } = DATABASE_GL.nonces[state];
    if (Date.now() >= expires_at) {
        delete DATABASE_GL.nonces[state];
       
        res.status(400).json({ error: 'this state has expired' });
        return;
    }

    let tokenSet;
    try {
        // Valida se o ID_TOKEN e o NONCE são válidos
        tokenSet = await googleClient.callback(
            GOOGLE_REDIRECT_URL,
            { id_token },
            { nonce }
        );
    } catch(error) {
        // Se o ID_TOKEN for inválido, retorne um erro
        res.status(400).json({ error: JSON.stringify(error) });
        return;
    }

    // Le as informações do ID_TOKEN
    const { sub, email } = tokenSet.claims();
    
    // Verifica se o usuário já esta cadastrado no banco de dados
    const user_id = `google-${sub}`;
    if (!DATABASE_GL.users[user_id]) {
        // Se não estiver, cadastra dele no banco de dados
        DATABASE_GL.users[user_id] = {
            id: user_id,
            email,
            created_at: Date.now(),
        };
    }

    // Cria um access_token opaco para o usuário logado
    const access_token = generators.random();
    const access_token_expires_at = Date.now() + (24 * 60 * 60 * 1000); // expira em 24 horas

    // Armazena o access_token no banco de dados
    DATABASE_GL.sessions[access_token] = {
        user_id: user_id,
        expires_at: access_token_expires_at,
    };

    // Retorna o access_token para o usuário logado
    res.status(200).json({
        access_token,
        expires_at: access_token_expires_at,
        token_type: 'Bearer'
    });
});

app.get('/oauth/codeChallenge', async (req, res) => {
    let { challenge_type } = req.body;

    // code_verifier
    const code_verifier = generators.codeVerifier();

    let code_challenge;
    // code_challenge do tipo S256
    if(challenge_type){
        if(challenge_type.startsWith("sha") && challenge_type.endsWith("256")){
            challenge_type = "sha-256";
            code_challenge = sha256(code_verifier).digest('base64url');
        }else{
            challenge_type = "plain";
            code_challenge = code_verifier;    
        }
    }else{
        challenge_type = "plain";
        code_challenge = code_verifier;
    }
    res.status(200).json({ challenge_type, code_challenge, code_verifier });
});

app.listen(port, () => {
    console.log(`App listening at http://localhost:${port}`)
})
