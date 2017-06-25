using System;
using System.Net;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SimpleWebServer;
using System.IO;
using JWT;
using OpenIDClient;
using OpenIDClient.Messages;

namespace OICClient
{
    class Client : OpenIdRelyingParty
    {
        // TODO specify the correct path
        public static string ROOT_PATH = @"..\..\..\..\";

        // TODO specify the correct URL
        public static string ISSUER = "https://mitreid.org";

        private string flow;
        private OIDCClientInformation clientInformation;
        private OIDCProviderMetadata providerMetadata;

        public Client(string clientMetadataString)
        {
            // TODO obtain provider configuration information
            // TODO register client
	    }

        public void authenticate(HttpListenerRequest req, HttpListenerResponse res, HTTPSession session)
        {
		    // use the session object to store state between requests
            session["nonce"] = RandomString();
            session["state"] = RandomString();
            
		    // TODO make authentication request
            
            // TODO insert the redirect URL
            string login_url = null;
            res.Redirect(login_url);
            res.Close();
	    }

        public void codeFlowCallback(HttpListenerRequest req, HttpListenerResponse res, HTTPSession session)
        {
		    // Callback redirect URI
		    String queryString = req.Url.Query;

		    // TODO parse authentication response from url
		    // TODO make token request
		    // TODO validate the ID Token according to the OpenID Connect spec (sec 3.1.3.7.)
		    // TODO make userinfo request

		    // TODO set the appropriate values
		    string authCode = null;
		    string accessToken = null;
		    OIDCIdToken idToken = null;
            OIDCUserInfoResponseMessage userInfoResponse = null;

            string responsePage = WebServer.successPage(authCode, accessToken, idToken, userInfoResponse);
            WebServer.SendResponse(req, res, responsePage);
	    }

        public void implicitFlowCallback(HttpListenerRequest req, HttpListenerResponse res, HTTPSession session)
        {
		    // Callback redirect URI
		    //String url = req.url() + "#" + req.queryParams("url_fragment");

		    // TODO parse authentication response from url
		    // TODO validate the ID Token according to the OpenID Connect spec (sec 3.2.2.11.)

		    // TODO set the appropriate values
            string authCode = null;
            string accessToken = null;
            OIDCIdToken idToken = null;
            OIDCUserInfoResponseMessage userInfoResponse = null;
	    }
    }
}
