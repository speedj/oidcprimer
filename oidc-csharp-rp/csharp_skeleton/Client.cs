using System;
using System.Net;
using System.Collections.Generic;
using SimpleWebServer;
using System.IO;
using JWT;
using OpenIDClient;
using OpenIDClient.Messages;

namespace OICClient
{
    class Client : OpenIdRelyingParty
    {
        IJsonSerializer JsonSerializer = new DefaultJsonSerializer();

        // TODO specify the correct path
        public static string ROOT_PATH = @"..\..\..\..\";

        // TODO specify the correct URL
        public static string ISSUER = null;

        private string flow;
        private OIDCClientInformation clientInformation;
        private OIDCProviderMetadata providerMetadata;

        public Client(string clientMetadataString)
        {
            // TODO obtain provider configuration information
            flow = "code";
            //flow = "token id_token";

            // To test with Google accounts, deccoment following line, configure an OpenID client on Google platform
            // and then add to client.json the cliend_id and client_secret obtained from Google.
            //ISSUER = "https://accounts.google.com";
            ISSUER = "https://mitreid.org";
            providerMetadata = ObtainProviderInformation(ISSUER);

            // TODO register client
            //JObject o = JObject.Parse(clientMetadataString);
            Dictionary<string, object> o = JsonSerializer.Deserialize<Dictionary<string, object>>(clientMetadataString);
            OIDCClientInformation clientMetadata = new OIDCClientInformation(o);
            if (clientMetadata.ClientId != null)
            {
                clientInformation = clientMetadata;
            }
            else
            {
                clientInformation = RegisterClient(providerMetadata.RegistrationEndpoint, clientMetadata);
            }
	    }

        public void authenticate(HttpListenerRequest req, HttpListenerResponse res, HTTPSession session)
        {
		    // use the session object to store state between requests
            session["nonce"] = RandomString();
            session["state"] = RandomString();

            // TODO make authentication request
            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = "openid profile email";
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.Nonce = (string)session["nonce"];
            requestMessage.State = (string)session["state"];
            requestMessage.ResponseType = clientInformation.ResponseTypes[0];

            // TODO insert the redirect URL
            string login_url = providerMetadata.AuthorizationEndpoint;
            login_url += "?" + requestMessage.serializeToQueryString(); 
            res.Redirect(login_url);
            res.Close();
	    }

        public void codeFlowCallback(HttpListenerRequest req, HttpListenerResponse res, HTTPSession session)
        {
		    // Callback redirect URI
		    String queryString = req.Url.Query;

		    // TODO parse authentication response from url
            OIDCAuthCodeResponseMessage responseMessage = ParseAuthCodeResponse(queryString, "openid", session["state"] as string);

		    // TODO make token request
            string authCode = responseMessage.Code;
            OIDCTokenRequestMessage tokenRequestMessage = new OIDCTokenRequestMessage();
            tokenRequestMessage.Scope = responseMessage.Scope;
            tokenRequestMessage.State = responseMessage.State;
            tokenRequestMessage.Code = authCode;
            tokenRequestMessage.ClientId = clientInformation.ClientId;
            tokenRequestMessage.ClientSecret = clientInformation.ClientSecret;
            tokenRequestMessage.GrantType = "authorization_code";
            for (int i = 0; i < clientInformation.ResponseTypes.Count; ++i)
            {
                if (clientInformation.ResponseTypes[i] == flow)
                {
                    tokenRequestMessage.RedirectUri = clientInformation.RedirectUris[i];
                }
            }
            OIDCTokenResponseMessage tokenResponse = SubmitTokenRequest(providerMetadata.TokenEndpoint, tokenRequestMessage, clientInformation);
            string accessToken = tokenResponse.AccessToken;

		    // TODO validate the ID Token according to the OpenID Connect spec (sec 3.1.3.7.)
            string jsonToken = JsonWebToken.Decode(tokenResponse.IdToken, accessToken, false);
            OIDCIdToken idToken = new OIDCIdToken();
            Dictionary<string, object> o = JsonSerializer.Deserialize<Dictionary<string, object>>(jsonToken);
            idToken.deserializeFromDynamic(o);
            ValidateIdToken(idToken, clientInformation, providerMetadata, session["nonce"] as string);

		    // TODO make userinfo request
            OIDCUserInfoRequestMessage userInfoRequestMessage = new OIDCUserInfoRequestMessage();
            userInfoRequestMessage.Scope = responseMessage.Scope;
            userInfoRequestMessage.State = responseMessage.State;
            OIDCUserInfoResponseMessage userInfoResponse = GetUserInfo(providerMetadata.UserinfoEndpoint, userInfoRequestMessage, accessToken);

		    // TODO set the appropriate values
            string responsePage = WebServer.successPage(authCode, accessToken, idToken, userInfoResponse);
            WebServer.SendResponse(req, res, responsePage);
	    }

        public void implicitFlowCallback(HttpListenerRequest req, HttpListenerResponse res, HTTPSession session)
        {
		    // Callback redirect URI
            string queryString = new StreamReader(req.InputStream).ReadToEnd();
            queryString = queryString.Replace("url_fragment=", "");
            queryString = Uri.UnescapeDataString(queryString);

		    // TODO parse authentication response from url
            OIDCAuthImplicitResponseMessage responseMessage = ParseAuthImplicitResponse(queryString, "openid", session["state"] as string);
            string accessToken = responseMessage.AccessToken;

		    // TODO validate the ID Token according to the OpenID Connect spec (sec 3.2.2.11.)
            string jsonToken = JsonWebToken.Decode(responseMessage.IdToken, accessToken, false);
            OIDCIdToken idToken = new OIDCIdToken();
            IJsonSerializer JsonSerializer = new DefaultJsonSerializer();
            Dictionary<string, object> o = JsonSerializer.Deserialize<Dictionary<string, object>>(jsonToken);
            idToken.deserializeFromDynamic(o);
            ValidateIdToken(idToken, clientInformation, providerMetadata, session["nonce"] as string);

            // TODO make userinfo request
            OIDCUserInfoRequestMessage userInfoRequestMessage = new OIDCUserInfoRequestMessage();
            userInfoRequestMessage.Scope = responseMessage.Scope;
            userInfoRequestMessage.State = responseMessage.State;
            OIDCUserInfoResponseMessage userInfoResponse = GetUserInfo(providerMetadata.UserinfoEndpoint, userInfoRequestMessage, accessToken);
            
            // TODO set the appropriate values
            string responsePage = WebServer.successPage(null, accessToken, idToken, userInfoResponse);
            WebServer.SendResponse(req, res, responsePage);
	    }
    }
}
