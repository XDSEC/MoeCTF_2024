<?php
error_reporting(0);
session_start();

if($_POST){
    $verify_code = $_POST['verify_code'];

    // 验证验证码
    if (empty($verify_code) || $verify_code !== $_SESSION['captcha_code']) {
        echo json_encode(array('status' => 0,'info' => '验证码错误啦，再输入吧'));
        unset($_SESSION['captcha_code']);
        exit;
    }

    $email = $_POST['email'];
    if(!preg_match("/[a-zA-Z0-9]+@[a-zA-Z0-9]+\\.[a-zA-Z0-9]+/", $email)||preg_match("/or/i", $email)){
        echo json_encode(array('status' => 0,'info' => '不存在邮箱为： '.$email.' 的管理员账号！'));
        unset($_SESSION['captcha_code']);
        exit;
    }

    $pwd = $_POST['pwd'];
    $pwd = md5($pwd);
    $conn = mysqli_connect("localhost","root","123456","xdsec",3306);


    $sql = "SELECT * FROM admin WHERE email='$email' AND pwd='$pwd'";
    $result = mysqli_query($conn,$sql);
    $row = mysqli_fetch_array($result);

    if($row){
        $_SESSION['admin_id'] = $row['id'];
        $_SESSION['admin_email'] = $row['email'];
        echo json_encode(array('status' => 1,'info' => '登陆成功，moectf{testflag}'));
    } else{
        echo json_encode(array('status' => 0,'info' => '管理员邮箱或密码错误'));
        unset($_SESSION['captcha_code']);
    }
}


?>