<?php

require_once __DIR__.'/../vendor/autoload.php';

$app = new Silex\Application();

$app->register(new Silex\Provider\TwigServiceProvider(), 
	       array(
		   'twig.path' => __DIR__.'/templates',
	       ));

$app->register(new Silex\Provider\SessionServiceProvider());

$app['oidc'] = function () use ($app) {
    if (null === $oidcclient = $app['session']->get('oidcclient')) {
	$oidc = new OpenIDConnectClient('https://mitreid.org/');
	$oidc->register();
	$app['session']-> set('oidcclient', array('client_id' => $oidc->getClientID(),
						  'client_secret' => $oidc->getClientSecret()));
	return $oidc;
    }
    return new OpenIDConnectClient('https://mitreid.org/',
				   $oidcclient['client_id'],
				   $oidcclient['client_secret']);
};


$app->get('/oidc-rp', function () use ($app) {
    $oidc = $app['oidc'];
    if ($oidc) {
        $auth_code = $oidc->authenticate();
        $name = $oidc->requestUserInfo('sub');
        return $app['twig']->render('oidc-rp.html',
				    array('auth_code' => $auth_code,
					  'access_token' => $oidc->getAccessToken(),
					  'id_token_claims' => $oidc->getIdTokenPayload(),
					  'userinfo' => $oidc->requestUserInfo()
					 )
				   );
    }
    $app->abort('500', 'Something went wrong with oidc, check console/web-container logs.');
  });

$app['debug'] = true;

$app->run();
