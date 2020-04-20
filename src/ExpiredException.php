<?php
namespace Firebase\JWT;

class ExpiredException extends \UnexpectedValueException implements IJWTException
{
    private $payload;
    
    public function __construct(object $payload, string $message = "", int $code = 0, Throwable $previous = NULL){
        parent::__construct($message, $code, $previous);
        $this->payload = $payload;
    }

    public function getPayload()
    {
        return $this->payload;
    }
}
