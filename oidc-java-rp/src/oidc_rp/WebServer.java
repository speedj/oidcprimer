package oidc_rp;

import static spark.Spark.exception;
import static spark.Spark.get;
import static spark.Spark.post;
import static spark.SparkBase.port;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;

import org.apache.commons.io.Charsets;

import com.google.common.collect.Maps;
import com.google.common.io.Resources;
import com.hubspot.jinjava.Jinjava;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;

/**
 * Skeleton code for building an OpenID Connect Public Client.
 *
 * Using the Spark (http://sparkjava.com/) as the webserver, and Nimbus OAauth
 * (http://connect2id.com/products/nimbus-oauth-openid-connect-sdk) for OpenID
 * Connect support.
 *
 * @author Rebecka Gulliksson, rebecka.gulliksson@umu.se
 *
 */
public class WebServer {
	/**
	 * Which port (on localhost) the RP listens to for the redirect URI.
	 */
	public static int SERVER_PORT = 8090;

	public static void main(String[] args) throws ParseException, IOException,
			URISyntaxException, SerializeException {
		
		String jsonMetadata = new String(Files.readAllBytes(Paths.get("/opt/oidcprimer/client.json")), Charsets.UTF_8);
		Client client = new Client(jsonMetadata);

		/*** Spark webserver setup ***/
		port(SERVER_PORT);

		/*** Spark webserver routes ***/

		/* displays the main page */
		get("/", (req, res) -> drawTemplate("index.html"));

		/*
		 * where the authentication response from the provider is received when
		 * using implicit or hybrid flow
		 */
		get("/implicit_flow_callback",
				(req, res) -> drawTemplate("repost_fragment.html"));

		/*
		 * starts authentication using the OpenID Connect code flow
		 */
		get("/authenticate", client::authenticate);

		/*
		 * where the authentication response from the provider is received when
		 * using code flow
		 */
		get("/code_flow_callback", client::codeFlowCallback);

		/*
		 * where the fragment identifier is received after being parsed by the
		 * client (using Javascript)
		 */
		post("/repost_fragment", client::implicitFlowCallback);

		/* default handling if a requested file can not be found */
		exception(IOException.class, (e, request, response) -> {
			response.status(404);
			response.body("Resource not found: " + e);
		});
	}
	
	private static String drawTemplate(String templateName) throws IOException {
		Jinjava jinjava = new Jinjava();
		Map<String, Object> context = Maps.newHashMap();

		String template = Resources.toString(Resources.getResource(templateName), Charsets.UTF_8);
		return jinjava.render(template, context);
	}

	/**
	 * Build HTML summary of a successful authentication flow.
	 *
	 * @param authCode
	 *            authorization code obtained from authentication response
	 * @param tokenResponse
	 *            response to the token request
	 * @param idTokenClaims
	 *            claims from the id token
	 * @param userInfoResponse
	 *            response to the user info request
	 * @return response containing HTML formatted summary.
	 */
	public static String successPage(AuthorizationCode authCode,
			AccessToken accessToken, String idToken,
			ReadOnlyJWTClaimsSet idTokenClaims,
			UserInfoSuccessResponse userInfoResponse) throws IOException {

		StringBuilder idTokenString = new StringBuilder();
		idTokenString.append(idTokenClaims.toJSONObject().toJSONString());
		idTokenString.append("\n");
		idTokenString.append(idToken);

		StringBuilder userInfoString = new StringBuilder();
		if (userInfoResponse != null) {
			userInfoString.append(userInfoResponse.getUserInfo().toJSONObject()
					.toJSONString());
			if (userInfoResponse.getContentType().equals(
					CommonContentTypes.APPLICATION_JWT)) {
				userInfoString.append("\n");
				userInfoString.append(userInfoResponse.getUserInfoJWT()
						.getParsedString());
			}
		} else {
			userInfoString.append("null");
		}
		
		Jinjava jinjava = new Jinjava();
		Map<String, Object> context = Maps.newHashMap();
		context.put("auth_code", authCode);
		context.put("access_token", accessToken);
		context.put("id_token_claims", idTokenString);
		context.put("userinfo", userInfoString);

		String template = Resources.toString(Resources.getResource("success_page.html"), Charsets.UTF_8);
		return jinjava.render(template, context);
	}
}
