<?php

require_once __DIR__.'/../vendor/autoload.php';

$app = new Silex\Application();

$app->register(new Silex\Provider\TwigServiceProvider(), 
	       array(
		   'twig.path' => __DIR__.'/templates',
	       ));

$app->register(new Silex\Provider\SessionServiceProvider());

$app->register(new Silex\Provider\MonologServiceProvider(), array(
    'monolog.logfile' => __DIR__.'/../development.log',
    'monolog.level'   => Monolog\Logger::INFO,
));

$app['oidc'] = function () use ($app) {
    $string = file_get_contents('../client.json');
    $client_config = json_decode($string, true);
    $oidc = array();

    $client_id = $client_config['client_id'];
    $client_secret = $client_config['client_secret'];
    
    if ($client_id and $client_secret) {
        $app['session']-> set('oidcclient', array(
            'client_id' => $client_id,
            'client_secret' => $client_secret,
        ));
    }
    
    if (null === $oidcclient = $app['session']->get('oidcclient')) {
        // TODO register with the provider using the client_metadata
        $oidc = new OpenIDConnectClient('https://mitreid.org/');
        $oidc->register($app, $client_config['redirect_uris'], $client_config['response_types']);
        $app['session']-> set('oidcclient', array(
            'client_id' => $oidc->getClientID(),
            'client_secret' => $oidc->getClientSecret()
        ));
    }
    else {
        $oidc = new OpenIDConnectClient(
            'https://mitreid.org/',
            $oidcclient['client_id'],
            $oidcclient['client_secret']
        );
    }

    $oidc->redirectURL = $client_config['redirect_uris'][0];
    $oidc->setResponseTypes([$client_config['response_types'][0]]);
    return $oidc;   				   
};

$app->get('/', function () use ($app) {
    $app['session']->clear();
    return $app['twig']->render('index.html');
    });

$app->get('/authenticate', function () use ($app) {
    $oidc = $app['oidc'];
    if ($oidc) {
        // TODO make authentication request
        $oidc->addScope("openid");
        $oidc->addScope("profile");
        $oidc->addScope("email");
        $auth_code = $oidc->authenticate();
    }
    $app->abort('500', 'Something went wrong with oidc, check console/web-container logs.');
  });

$app->get('/code_flow_callback', function () use ($app) {
    $oidc = $app['oidc'];
    if ($oidc) {
        // TODO parse the authentication response
        $auth_code = $oidc->authenticate();
        $id_token = $oidc->getIdToken();

        // TODO make userinfo request
        $userinfo = json_encode($oidc->requestUserInfo());

        // TODO set the appropriate valuesa
        $access_token = $oidc->getAccessToken();
        return $app['twig']->render('success_page.html', array(
            'client_id' => $oidc->getClientID(),
            'client_secret' => $oidc->getClientSecret(),
            'auth_code' => $auth_code,
            'access_token' => $access_token,
            'id_token_claims' => $id_token,
            'userinfo' => $userinfo,
        ));
    }
    $app->abort('500', 'Something went wrong with oidc, check console/web-container logs.');
  });

$app->post('/repost_fragment', function () use ($app) {
    return $app['twig']->render('repost_fragment.html');
    });

$app['debug'] = true;

$app->run();
