<?php
require 'vendor/autoload.php';

$modes = require __DIR__ . '/helpers/modes.php';
$ciphers = require __DIR__ . '/helpers/ciphers.php';

function proctime($t)
{
    return microtime(true) - $t;
}

function msg($msg, $break = true)
{
    echo number_format(microtime(true), 4, '.', '') . ": $msg" . ($break ? PHP_EOL : '');
}

$out = array();

for ($pass = 1; $pass <= 3; $pass++) {
    foreach (array(1, 10, 100, 1000) as $kb) {

        if (!isset($out[$kb])) {
            $out[$kb] = array();
        }

        $blob = str_repeat('A', 1024 * $kb);
        foreach ($modes as $mode) {

            if (!isset($out[$kb][$mode])) {
                $out[$kb][$mode] = array();
            }

            foreach ($ciphers as $cipher) {
                msg("Pass:$pass size:$kb mode:$mode cipher:$cipher");
                if (!isset($out[$kb][$mode][$cipher])) {
                    $out[$kb][$mode][$cipher] = 0;
                }

                $t = microtime(true);
                $c = \Dcrypt\Aes::encrypt($blob, 'AAAAAAAA');
                $d = proctime($t);
                $o = $out[$kb][$mode][$cipher];

                if ($o === 0) {
                    $out[$kb][$mode][$cipher] = $d;
                } else {
                    $out[$kb][$mode][$cipher] = ($o + $d) / 2;
                }
            }
        }
    }
}
ob_start();
?>
<html>
    <head>
        <script src = "http://cdn.kendostatic.com/2014.1.318/js/kendo.all.min.js"></script>
    </head>
    <body>

        <?php
        foreach ($out as $size => $a) {
            echo '<h1>' . $size . ' kb</h1>';
            foreach ($a as $b => $c) {
                echo '<h4>mode: ' . $b . '</h4>';
                ?>
                <table>
                    <?php
                    foreach ($c as $d => $e) {
                        ?>
                        <tr>
                            <td>
                                <?php echo $d ?>
                            </td>
                            <td>
                                <?php echo number_format($e, 8) ?>
                            </td>
                        </tr>
                        <?php
                    }
                    ?>
                </table>
                <?php
            }
        }
        ?>

    </body>
</html>
<?php
file_put_contents('benchmark.html', ob_get_clean());
