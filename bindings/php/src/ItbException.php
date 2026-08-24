<?php

declare(strict_types=1);

namespace Everanium\Itb;

/**
 * Exception type shared by every fallible call in the binding.
 *
 * getStatus() carries the libitb status code when the failure came
 * from the shared library (null for binding-side failures such as a
 * library-load error). getDetail() carries the ITB_LastError
 * diagnostic captured immediately after the failing call
 * (process-global last-write-wins — the message may belong to a
 * different call under concurrent FFI use; the status code is always
 * attributable).
 */
class ItbException extends \RuntimeException
{
    /** @var int|null */
    private $status;

    /** @var string */
    private $detail;

    public function __construct(string $detail, ?int $status = null)
    {
        $this->status = $status;
        $this->detail = $detail;
        if ($status === null) {
            $text = 'itb: ' . $detail;
        } elseif ($detail !== '') {
            $text = sprintf('itb: status=%d (%s): %s', $status, Status::label($status), $detail);
        } else {
            $text = sprintf('itb: status=%d (%s)', $status, Status::label($status));
        }
        parent::__construct($text, $status ?? 0);
    }

    /** The libitb status code, or null for a binding-side failure. */
    public function getStatus(): ?int
    {
        return $this->status;
    }

    /** The ITB_LastError diagnostic text ('' when none was recorded). */
    public function getDetail(): string
    {
        return $this->detail;
    }
}
