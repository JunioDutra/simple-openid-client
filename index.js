import axios from "axios";
import crypto from "crypto";

const CLIENT_TYPE = "PUBLIC";

class OpenIdClientClass {
  wellKnowUrls;
  tokens;
  configs = null;
  codeVerifier;

  constructor() { }

  async init(configs) {
    if (!configs) throw new Error("missing configuration params");

    this.configs = configs;

    if (!configs.client_secret) {
      this.configs.type = CLIENT_TYPE;
    }

    const { data } = await axios.get(
      `${this.configs?.authority}/.well-known/openid-configuration`
    );

    this.wellKnowUrls = data;
  }

  async getRedirectUrl() {
    let redirectUrl = `${this.wellKnowUrls.authorization_endpoint
      }?scope=openid&response_type=${this.configs?.response_types.join(
        ","
      )}&client_id=${this.configs?.client_id
      }&redirect_uri=${this.configs?.redirect_uris?.join(",")}`;

    if (this.configs.type === CLIENT_TYPE) {
      this.codeVerifier = this.createCodeVerifier()
      const codeChallenge = this.createCodeChallenge(this.codeVerifier)

      redirectUrl += `&code_challenge=${codeChallenge}&code_challenge_method=S256`
    }

    return redirectUrl;
  }

  async getTokens(code) {
    const tokenUrl = `${this.wellKnowUrls.token_endpoint}?grant_type=${this.configs?.grant_type
      }&code=${code}&redirect_uri=${this.configs?.redirect_uris?.join(",")}${this.codeVerifier ? `&code_verifier=${this.codeVerifier}&client_id=${this.configs.client_id}` : ''}`;

    const headers = {
      "Content-Type": "application/x-www-form-urlencoded",
    };

    if (!this.codeVerifier) {
      this.headers.Authorization = `Basic ${Buffer.from(
        `${this.configs?.client_id}:${this.configs?.client_secret}`
      ).toString("base64")}`;
    }

    try {
      const { data } = await axios.post(tokenUrl, {}, { headers });
      this.tokens = data;
      return data;
    } catch (error) {
      const loginUrl = await this.getRedirectUrl();
      window.location.assign(loginUrl);
    }
  }

  async getUserInfo() {
    const authHeader = {
      Authorization: `${this.tokens.token_type} ${this.tokens.access_token}`,
    };

    const { data } = await axios.get(this.wellKnowUrls.userinfo_endpoint, {
      headers: authHeader,
    });

    return data;
  }

  createCodeVerifier() {
    return this.base64URLEncode(crypto.randomBytes(32));
  }

  createCodeChallenge(verifier) {
    function sha256(buffer) {
      return crypto.createHash('sha256').update(buffer).digest();
    }

    return this.base64URLEncode(sha256(verifier));
  }

  base64URLEncode(str) {
    return str.toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
}

const OpenIdClient = new OpenIdClientClass();

export { OpenIdClient };