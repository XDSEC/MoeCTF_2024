<?php

class A {
    // 注意 private 属性的序列化哦
    private $evil;

    // 如何赋值呢
    private $a;

    function __destruct() {
        $s = $this->a;
        $s($this->evil);
    }
}

class B {
    private $b;

    function __invoke($c) {
        $s = $this->b;
        $s($c);
    }
}


 if(isset($_GET['data']))
 {
     $a = unserialize($_GET['data']);
 }
 else {
     highlight_file(__FILE__);
 }
