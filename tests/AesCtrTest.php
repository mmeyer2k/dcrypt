<?php declare(strict_types=1);

class AesCtrTest extends AesBase
{
    public static $vectors = [
        'E4M3ierx8R27AudHgecE3r42KxLe9qd85AKG1wYo94rVzJ+adUgZdjS6yY9/T2XjlqsDk1qabES74VXQ',
        'fysIOWwcwB/y07sxrV6njouA/TxKsNkfifVjJRVP/SolO2Q2N3f0ULOTUpMOlKgEO0esEEzp+pgDKjf6',
        '+VUBy1RRV+dg/o3LLuau562McjWNNCguTwVoB/SG96t8HuU7xR4i/Yi5K/uAzFO8VYPQxNBduuA3zeR0',
    ];

    public static $class = '\\Dcrypt\\AesCtr';
}
