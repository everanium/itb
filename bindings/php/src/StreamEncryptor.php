<?php

declare(strict_types=1);

namespace Everanium\Itb3;

/** Incremental encrypt session: plaintext in, wire out. */
final class StreamEncryptor extends StreamSession
{
    protected const BEGIN = 'ITB_Triple_EncryptStreamBegin';
}
