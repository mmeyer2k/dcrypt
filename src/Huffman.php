<?php

namespace Dcrypt;

class Huffman
{

    /**
     * Compress data
     *
     * @param string $data
     * @return string
     */
    public static function encode($data)
    {
        $dictionary = self::frequencyMap($data);

        $binaryString = '';

        $indexMap = self::createBinaryIndexes(count($dictionary));

        // Map the binary data to the index
        foreach (str_split($data) as $d) {
            // Find character position in dictionary array
            $pos = array_search(base64_encode($d), array_keys($dictionary));

            // Append the binary to the running string
            $binaryString = $binaryString . $indexMap[$pos];
        }

        // Pad the string to the byte boundry
        while (strlen($binaryString) % 8 !== 0) {
            $binaryString = $binaryString . '0';
        }

        // Chunk data into bytes
        $chunks = str_split($binaryString, 8);

        // Pack the binary string
        foreach ($chunks as $i => &$chunk) {
            $padded = str_pad($chunk, 8, '0', STR_PAD_RIGHT);
            $chunk = chr(bindec($padded));
        }

        // Return compressed data with packed dictionary
        return self::packDictionary($dictionary) . implode($chunks);
    }

    /**
     * Decompress data
     *
     * @param string $data
     * @return string
     */
    public static function decode($data)
    {
        $dictionary = self::unpackDictionary($data);

        // Remove dictionary bytes from beginning of data
        $data = str_split(substr($data, count($dictionary) * 2 + 1));

        $binary = '';

        // Convert data to binary
        while ($data) {
            $b = decbin(ord(array_shift($data)));

            // Pad to the left with zeros
            $b = str_pad($b, 8, '0', STR_PAD_LEFT);

            $binary .= $b;
        }

        $binary = str_split($binary);

        $pop = '';
        $out = '';

        while ($binary) {
            $pop .= array_shift($binary);
            if (isset($dictionary[$pop])) {
                $out .= $dictionary[$pop];
                $pop = '';
            }
        }

        return $out;
    }

    /**
     * Creates a packed dictionary.
     *
     * @param array $dictionary
     * @return string
     */
    private static function packDictionary(array $dictionary)
    {
        // First byte will be the count of items in the dictionary
        $out = chr(count($dictionary));

        // Get the binary index mapping
        $indexMap = self::createBinaryIndexTree(count($dictionary));

        $dictionary = array_keys($dictionary);

        foreach ($dictionary as $idx => $char) {
            $out = $out . chr(bindec($indexMap[$idx])) . base64_decode($char);
        }

        return $out;
    }

    /**
     * Unpack dictionary
     *
     * @param $data
     * @return array
     */
    private static function unpackDictionary($data)
    {
        // Get first byte which is dictionary size
        $count = ord(substr($data, 0, 1));
        $packedBytes = str_split(substr($data, 1, $count * 2));

        $out = [];

        while ($packedBytes) {
            $idx = array_shift($packedBytes);
            $val = array_shift($packedBytes);

            $out[decbin(ord($idx))] = $val;
        }

        return $out;
    }

    /**
     * Returns a bit mapping array like this:
     *
     * 100
     * 101
     * 111
     *
     * @param $count
     * @return array
     */
    private static function createBinaryIndexes($count)
    {
        // Start a counter to base our binary frame on
        $startOffset = 0;

        // Start a loop that we will manually break out of
        while (1) {
            $out = array();

            foreach (range(1, $count) as $range) {
                $out[] = decbin($startOffset + $range);
            }

            // Make sure that no index is the prefix of any another
            $found = false;
            foreach ($out as $v1) {
                foreach ($out as $v2) {
                    if ($v1 !== $v2 && starts_with($v1, $v2)) {
                        $found = true;
                    }
                }
            }

            // Once a mapping is accepted, return it as an array
            if (!$found) {
                return $out;
            }

            // ... otherwise, try again from the next highest position
            $startOffset = $startOffset + 1;
        }
    }

    /**
     * Map character frequency as array. Returns array like this:
     *
     * array(
     * 
     * )
     *
     * @param string $data
     * @return array
     */
    private static function frequencyMap($data)
    {
        $occurences = array();

        while (isset($data[0])) {
            // Count occurences for the first char and add to frequency map
            $occurences[base64_encode($data[0])] = substr_count($data, $data[0]);

            $data = str_replace($data[0], '', $data);
        }

        // Sort the resulting array
        asort($occurences);

        // Return the array in descending order
        return array_reverse($occurences);
    }
}
