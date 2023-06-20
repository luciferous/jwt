<?php

namespace Firebase\JWT;

class BeforeValidException extends \UnexpectedValueException implements JwtExceptionInterface
{
    private $payload;

    public function setPayload(object $payload): void
    {
        $this->payload = $payload;
    }

    public function getPayload(): object
    {
        return $this->payload;
    }
}
