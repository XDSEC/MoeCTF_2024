<?php
$url = $_GET['url'];

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_HEADER, false);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);

$res = curl_exec($ch);

$image_info = getimagesizefromstring($res);
$mime_type = $image_info['mime'];

header('Content-Type: ' . $mime_type);

curl_close($ch);

echo $res;
?>
