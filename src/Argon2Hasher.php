<?php

namespace dvaun\LaravelArgon2;

use RuntimeException;
use Illuminate\Contracts\Hashing\Hasher as HasherContract;

class Argon2Hasher implements HasherContract
{
    /**
     * Default memory cost factor.
     *
     * @var int
     */
    protected $memoryCost = 1024;

    /**
     * Default time cost factor.
     *
     * @var int
     */
    protected $timeCost = 3;

    /**
     * Default threads factor.
     *
     * @var int
     */
    protected $threads = 1;

    /**
     * Hash the given value.
     *
     * @param  string $value
     * @param  array  $options
     * @return string
     * @throws RuntimeException
     */
    public function make($value, array $options = [])
    {
        $memoryCost = $options['memory_cost'] ?? $this->memoryCost;
        $timeCost = $options['time_cost'] ?? $this->timeCost;
        $threads = $options['threads'] ?? $this->threads;

        $options = [
            m_cost: $memoryCost
            t_cost: $timeCost
            threads: 1
        ]

        $hash = argon2_hash($value [, $algorithm = HASH_ARGON2I] 
            [, $options ]
            [, $raw = false]
        );

        if ($hash === false) {
            throw new RuntimeException('Argon2i hashing not supported.');
        }

        return $hash;
    }

    /**
     * Check the given plain value against a hash.
     *
     * @param  string $value
     * @param  string $hashedValue
     * @param  array  $options
     * @return bool
     */
    public function check($value, $hashedValue, array $options = [])
    {
        if (strlen($hashedValue) === 0) {
            return false;
        }

        return argon2_verify($value, $hashedValue);
    }

    /**
     * Check if the given hash has been hashed using the given options.
     *
     * @param  string $hashedValue
     * @param  array  $options
     * @return bool
     */
    public function needsRehash($hashedValue, array $options = [])
    {
        set_error_handler(function($errno, $errstr, $errfile, $errline, array $errcontext) {
            // error was suppressed with the @-operator
            if (0 === error_reporting()) {
                return false;
            }
        
            throw new ErrorException($errstr, 0, $errno, $errfile, $errline);
        });
        $pass = false;
        try {
            $pass = argon2_verify($value, $hashedValue);
        }
        catch (ErrorException $e) {
            $pass = false;
        }
        restore_error_handler();
        return $pass;
    }

    /**
     * Set the default memory cost factor.
     *
     * @param $memoryCost
     * @return $this
     */
    public function setMemoryCost($memoryCost)
    {
        $this->memoryCost = (int) $memoryCost;

        return $this;
    }

    /**
     * Set the default time cost factor.
     *
     * @param $timeCost
     * @return $this
     */
    public function setTimeCost($timeCost)
    {
        $this->timeCost = (int) $timeCost;

        return $this;
    }

    /**
     * Set the default threads factor.
     *
     * @param $threads
     * @return $this
     */
    public function setThreads($threads)
    {
        $this->threads = (int) $threads;

        return $this;
    }
}
