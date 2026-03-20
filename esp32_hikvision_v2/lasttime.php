<?php
/**
 * lasttime.php
 *
 * - When called with ?time=...&device=... it saves the time to a file per device.
 * - When called with ?device=... (no time param) it returns the last saved time.
 */

$device = isset($_GET['device']) ? preg_replace('/[^a-zA-Z0-9_\-]/', '', $_GET['device']) : 'default';
$file = __DIR__ . "/lasttime_{$device}.txt";

if (isset($_GET['time']) && $_GET['time'] !== '') {
    $time = $_GET['time'];
    file_put_contents($file, $time);
    echo "OK";
} else {
    if (file_exists($file)) {
        echo file_get_contents($file);
    } else {
        echo "";
    }
}
