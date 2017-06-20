<?php

// web/index.php
require_once __DIR__.'/../vendor/autoload.php';

$app = new Silex\Application();

$app->register(new Silex\Provider\TwigServiceProvider(), 
	       array(
		     'twig.path' => __DIR__.'/templates',
		     ));

$app->register(new Silex\Provider\SessionServiceProvider());

$app->get('/hello/{name}', function ($name) use ($app) {
    return 'Hello '.$app->escape($name);
  });

$app['oidc-rp'] = function() {
  return new OpenIDConnectClient('https://mitreid.org/');
};

$app->get('/twighello/{name}', function ($name) use ($app) {
    return $app['twig']->render('twighello.html', 
				array(
				      'name' => $name,
				      ));
  });

$app->get('/oidc-rp', function () use ($app) {
    $oidc = $app['oidc-rp'];
    if (null === $oidcclient = $app['session']->get('oidcclient')) {
      $oidc->register();
      $app['session']-> set('oidcclient', array('client_id' => $oidc->getClientID(),
					      'client_secret' => $oidc->getClientSecret()));
      return $app->redirect('/oidc-rp');
    } 
    $oidc->setClientID($oidcclient['client_id']);
    $oidc->setClientSecret($oidcclient['client_secret']);
    $oidc->authenticate();
    $name = $oidc->requestUserInfo('sub');
    return 'Hello '.$app->escape($name);
  });

/**
$app->get('/oidc-rp', function () use ($app) {
    $oidcclient = $app['session']->get('oidcclient');

    $oidc = $app['oidc-rp'];

  });
*/

$app['debug'] = true;



$app->run();
