<?php

// web/index.php
require_once __DIR__.'/../vendor/autoload.php';

$app = new Silex\Application();

$app->register(new Silex\Provider\TwigServiceProvider(), 
	       array(
		     'twig.path' => __DIR__.'/templates',
		     ));

$app->get('/hello/{name}', function ($name) use ($app) {
    return 'Hello '.$app->escape($name);
  });


$app->get('/twighello/{name}', function ($name) use ($app) {
    return $app['twig']->render('twighello.html', 
				array(
				      'name' => $name,
				      ));
  });

$app['debug'] = true;

$app->run();
