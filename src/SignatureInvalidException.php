<?php

namespace Firebase\JWT;

class SignatureInvalidException extends \UnexpectedValueException implements JwtExceptionInterface
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
