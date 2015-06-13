<?php

error_reporting(E_ALL | E_STRICT);

if (!@include __DIR__ . '/../vendor/autoload.php') {
    die(<<<'DIE'
You must set up the project dependencies, run the following commands:
    wget http://getcomposer.org/composer.phar
    php composer.phar install
DIE
    );
}
