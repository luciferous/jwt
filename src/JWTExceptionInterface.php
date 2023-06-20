<?php
namespace Firebase\JWT;

interface JWTExceptionInterface
{
    /**
     * Get the payload that caused this exception.
     *
     * @return object
     */
    public function getPayload();
}
