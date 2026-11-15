<?php
$name = htmlspecialchars($_POST['name'] ?? '', ENT_QUOTES, 'UTF-8');
$msg = htmlspecialchars($_POST['message'] ?? '', ENT_QUOTES, 'UTF-8');
if ($name && $msg) {
    file_put_contents(__DIR__ . '/messages.log', date('c') . " $name: $msg\n", FILE_APPEND | LOCK_EX);
    echo 'Thanks!';
}
