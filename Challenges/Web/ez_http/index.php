<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ez_http</title>
    <style>
        body, html {
            margin: 0;
            padding: 0;
            width: 100%;
            height: 100%;
            display: flex;
            justify-content: center;
            align-items: center;
            font-family: 'Arial', sans-serif;
            overflow: hidden;
            background-size: cover;
            background-position: center;
            animation: changeBackground 10s infinite;
        }

        .container {
            text-align: center;
        }

        .title {
            font-size: 4em;
            color: white;
            margin-bottom: 20px;
            animation: fadeIn 2s ease-in-out, bounce 2s;
        }

        .button {
            padding: 10px 20px;
            font-size: 1.5em;
            color: #ff7e5f;
            background-color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            transition: transform 0.3s ease-in-out;
        }

        .button:hover {
            transform: scale(1.1);
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        @keyframes bounce {
            0%, 20%, 50%, 80%, 100% {
                transform: translateY(0);
            }
            40% {
                transform: translateY(-30px);
            }
            60% {
                transform: translateY(-15px);
            }
        }

        @keyframes changeBackground {
            0% { background-image: url('image1.jpg'); }
            25% { background-image: url('image2.jpg'); }
            50% { background-image: url('image3.jpg'); }
            75% { background-image: url('image4.jpg'); }
            100% { background-image: url('image1.jpg'); }
        }
    </style>
</head>
<body>
    <div class="container">
        <form method="get">
            <button class="button" name="animateButton">Hit the question setter</button>
        </form>
        <?php
        error_reporting(0);
        $msg = "";
        $images = ['image1.jpg', 'image2.jpg', 'image3.jpg', 'image4.jpg'];
        $randomImage = $images[array_rand($images)];
        echo "<style>body { background-image: url('$randomImage'); }</style>";

        if ($_SERVER['REQUEST_METHOD'] == 'GET' && isset($_GET['animateButton'])) {
            echo '<h1 class="title">big胆</h1>';
        } elseif ($_SERVER['REQUEST_METHOD'] == 'GET') {
            $msg = '<h1 class="title">Please use POST method</h1>';
            exit($msg);
        } else {
            if (!isset($_POST['imoau'])) {
                $msg = '<h1 class="title">Please POST the parameter imoau=sb</h1>';
                exit($msg);
            } else {
                if ($_POST['imoau'] != 'sb') {
                    $msg = '<h1 class="title">POST parameter error</h1>';
                    exit($msg);
                } else {
                    if (!isset($_GET['xt'])) {
                        $msg = "<h1 class='title'>Please GET the parameter xt=大帅b</h1>";
                        exit($msg);
                    } else {
                        if ($_GET['xt'] != '大帅b') {
                            $msg = "<h1 class='title'>GET parameter error</h1>";
                            exit($msg);
                        } else {
                            if ($_SERVER['HTTP_REFERER'] != 'https://www.xidian.edu.cn/') {
                                $msg = "<h1 class='title'>The source must be https://www.xidian.edu.cn/</h1>";
                                exit($msg);
                            } else {
                                if (!isset($_COOKIE['user'])) {
                                    $msg = "<h1 class='title'>Please set cookie: user=admin</h1>";
                                    exit($msg);
                                } else {
                                    if ($_COOKIE['user'] != 'admin') {
                                        $msg = "<h1 class='title'>Cookie error</h1>";
                                        exit($msg);
                                    } else {
                                        if ($_SERVER['HTTP_USER_AGENT'] != 'MoeDedicatedBrowser') {
                                            $msg = "<h1 class='title'>Please use MoeDedicatedBrowser</h1>";
                                            exit($msg);
                                        } else {
                                            if ($_SERVER['HTTP_X_FORWARDED_FOR'] != '127.0.0.1') {
                                                $msg = "<h1 class='title'>Local access only</h1>";
                                                exit($msg);
                                            } else {
                                                $msg = "<h1 class='title'>Here is your flag: moectf{testflag}</h1>";
                                                echo $msg;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        ?>
    </div>
</body>
</html>
