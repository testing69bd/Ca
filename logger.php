<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $number = $_POST['number'] ?? 'unknown';
        $ua = $_POST['ua'] ?? 'unknown';
            $log = "[" . date("Y-m-d H:i:s") . "] Number: $number | User-Agent: $ua\n";

                file_put_contents("log.txt", $log, FILE_APPEND);
                }