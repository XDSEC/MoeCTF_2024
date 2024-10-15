<?php
highlight_file('final1l1l_challenge.php');
error_reporting(0);
include 'flag.php';

$a = $_GET['a'];
$b = $_POST['b'];
if (isset($a) && isset($b)) {
    if (!is_numeric($a) && !is_numeric($b)) {
        if ($a == 0 && md5($a) == $b[$a]) {
            echo $flag;
        } else {
            die('noooooooooooo');
        }
    } else {
        die( 'Notice the param type!');
    }
} else {
    die( 'Where is your param?');
}