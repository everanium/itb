<?php

declare(strict_types=1);

namespace Everanium\Itb;

/** Incremental decrypt session: wire in, plaintext out. */
final class StreamDecryptor extends StreamSession
{
    protected const BEGIN = 'ITB_Triple_DecryptStreamBegin';
}
