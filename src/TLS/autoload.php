<?php
spl_autoload_register(function(string $cls){
  $cls = str_replace('nwniscoding\\TLS', './', $cls);

  require_once "$cls.php";
});