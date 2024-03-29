<?php

return [

    'default' => 'sqlsrv',

    'connections' => [
        'sqlsrv' => [
            'driver'    => 'sqlsrv',
            'host'      => env('DB_HOST'),
            'port'      => env('DB_PORT'),
            'database'  => env('DB_DATABASE'),
            'username'  => env('DB_USERNAME'),
            'password'  => env('DB_PASSWORD'),
            'charset'   => 'utf8',
            'collation' => 'utf8_unicode_ci',
            'prefix'    => '',
            'strict'    => false,
        ],

        'sqlsrv1' => [
            'driver'    => 'sqlsrv',
            'host'      => env('DB1_HOST'),
            'port'      => env('DB1_PORT'),
            'database'  => env('DB1_DATABASE'),
            'username'  => env('DB1_USERNAME'),
            'password'  => env('DB1_PASSWORD'),
            'charset'   => 'utf8',
            'collation' => 'utf8_unicode_ci',
            'prefix'    => '',
            'strict'    => false,
        ],

        'sqlsrv2' => [
            'driver'    => 'sqlsrv',
            'host'      => env('DB2_HOST'),
            'port'      => env('DB2_PORT'),
            'database'  => env('DB2_DATABASE'),
            'username'  => env('DB2_USERNAME'),
            'password'  => env('DB2_PASSWORD'),
            'charset'   => 'utf8',
            'collation' => 'utf8_unicode_ci',
            'prefix'    => '',
            'strict'    => false,
        ],
    ],
];
