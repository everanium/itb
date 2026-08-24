<?php

/**
 * Composer-free PSR-4 autoloader for the Everanium\Itb namespace.
 * Used by the in-repo test / bench / eitb entry points; composer
 * consumers get the same mapping from composer.json instead.
 */

declare(strict_types=1);

spl_autoload_register(static function (string $class): void {
    $prefix = 'Everanium\\Itb\\';
    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }
    $relative = substr($class, strlen($prefix));
    $file = __DIR__ . '/src/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($file)) {
        require $file;
    }
});
