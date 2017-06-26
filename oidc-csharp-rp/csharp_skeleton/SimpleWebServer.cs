using System;
using System.Net;
using System.Threading;
using System.Linq;
using System.IO;
using System.Text;
using System.Collections.Generic;
using OICClient;
using OpenIDClient.Messages;

namespace SimpleWebServer
{
    public class WebServer
    {
        private readonly HttpListener _listener = new HttpListener();
        private Dictionary<string, Action<HttpListenerRequest, HttpListenerResponse, HTTPSession>> actions;
        private Dictionary<string, HTTPSession> sessions;

        public WebServer(int port)
        {
            if (!HttpListener.IsSupported)
            {
                throw new NotSupportedException("Needs Windows XP SP2, Server 2003 or later.");
            }

            sessions = new Dictionary<string, HTTPSession>();

			String jsonMetadata = File.ReadAllText(Path.Combine(Client.ROOT_PATH + "client.json"));
            Client client = new Client(jsonMetadata);

            actions = new Dictionary<string, Action<HttpListenerRequest, HttpListenerResponse, HTTPSession>>();
            actions.Add("/", ReadFromFile);
            actions.Add("/implicit_flow_callback", ReadFromFile);
            actions.Add("/authenticate", client.authenticate);
            actions.Add("/code_flow_callback", client.codeFlowCallback);
            actions.Add("/repost_fragment", client.implicitFlowCallback);

            _listener.Prefixes.Add("http://localhost:" + port + "/");
            _listener.Start();
        }

        public void Run()
        {
            ThreadPool.QueueUserWorkItem((o) =>
            {
                Console.WriteLine("Webserver running...");
                try
                {
                    while (_listener.IsListening)
                    {
                        ThreadPool.QueueUserWorkItem((c) =>
                        {
                            var ctx = c as HttpListenerContext;
                            if (!actions.Keys.Contains(ctx.Request.Url.LocalPath))
                            {
                                ctx.Response.StatusCode = 404;
                                ctx.Response.StatusDescription = "Error, page not found";
                                SendResponse(ctx.Request, ctx.Response, "Error, page not found");
                                return;
                            }

                            try
                            {
                                HTTPSession session;
                                Cookie sessionIdCookie = ctx.Request.Cookies["ss-id"];
                                if (sessionIdCookie == null || !sessions.Keys.Contains(sessionIdCookie.Value as string))
                                {
                                    string sessionid = new Random().Next().ToString();
                                    session = new HTTPSession();
                                    sessions.Add(sessionid, session);
                                    sessionIdCookie = new Cookie("ss-id", sessionid);
                                    ctx.Response.Cookies.Add(sessionIdCookie);
                                }
                                else
                                {
                                    session = sessions[sessionIdCookie.Value as string];
                                }

                                actions[ctx.Request.Url.LocalPath](ctx.Request, ctx.Response, session);
                            }
                            catch (Exception e)
                            {
                                string message = "Internal server error: " + e.Message;
                                ctx.Response.StatusCode = 500;
                                Console.WriteLine(message + "\n" + e.StackTrace);
                                ctx.Response.StatusDescription = message;
                                SendResponse(ctx.Request, ctx.Response, message);
                            }
                        }, _listener.GetContext());
                    }
                }
                catch
                {
                    // suppress any exceptions
                }
            });
        }

        public void Stop()
        {
            _listener.Stop();
            _listener.Close();
        }

        public static void ReadFromFile(HttpListenerRequest request, HttpListenerResponse response, HTTPSession session)
        {
            string fileName = null;
            switch (request.Url.LocalPath)
            {
                case "/":
                    fileName = "index.html";
                    break;
                case "/implicit_flow_callback":
                    fileName = "repost_fragment.html";
                    break;
                default:
                    throw new Exception("Wrong filename.");
            }

			SendResponse(request, response, File.ReadAllText(Path.Combine(Client.ROOT_PATH, "oidc-csharp-rp", "templates", fileName)));
        }

        public static void SendResponse(HttpListenerRequest request, HttpListenerResponse response, String rstr)
        {
            byte[] buf = Encoding.UTF8.GetBytes(rstr);
            response.ContentLength64 = buf.Length;
            response.OutputStream.Write(buf, 0, buf.Length);
            response.OutputStream.Close();
        }

        public static string successPage(string authCode, string accessToken, OIDCIdToken idToken, OIDCUserInfoResponseMessage userInfoResponse)
        {
            string stringIdToken = idToken.serializeToJsonString();
            string userInfoString = userInfoResponse.serializeToJsonString();
			String successPage = File.ReadAllText(Path.Combine(Client.ROOT_PATH, "oidc-csharp-rp", "templates", "success_page.html"));
            return String.Format(successPage, authCode, accessToken, stringIdToken, userInfoString);
        }
    }

    public class HTTPSession
    {
        Dictionary<string, object> session;

        public HTTPSession()
        {
            session = new Dictionary<string, object>();
        }

        public object this[string key]
        {
            get
            {
                return session[key];
            }
            set
            {
                session[key] = value;
            }
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            int port = 8090;
            WebServer ws = new WebServer(port);
            ws.Run();
            Console.WriteLine($"A simple webserver started on port {port}. Press a key to quit.");
            Console.ReadKey();
            ws.Stop();
        }

    }
}