<html>
<head><title>RP Auth Success</title></head>
<body>

Access token:
<pre>
	<?php
		echo $_SERVER['OIDC_access_token'];
	?>		
</pre>

OIDC Claims
<pre>
<?php
foreach ( $_SERVER as $key=>$value) {
  if (strpos($key, 'OIDC_CLAIM') === 0) {
    echo "\t".$key." = ".$value."\n";
  }
}
?>
</pre>

User info:
<a href="http://localhost:8090/protected/redirect_uri?info=json">
	http://localhost:8090/protected/redirect_uri?info=json
</a>

</body>
</html>

