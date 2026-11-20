<?php
// artex-lab fixture: keep the request alive so upload-progress updates fire.
if (session_status() === PHP_SESSION_NONE) { session_start(); }
$t0 = microtime(true);
while (microtime(true) - $t0 < 3.0) { usleep(50000); }
echo "FIXTURE-OK\n";
