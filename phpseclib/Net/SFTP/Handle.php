<?php
// instead of passing a copy of $sftp we could pass the original $sftp probably
// what would we do for the 3.0 branch tho? we could use traits but dealing with the private variables would still be super messy
//    maybe we could have all the private / protected methods live in Net\Common\SFTP.php. Net\SFTP.php could extend the new class as could Net\SFTP\Handle.php
// if this works could we rewrite get() and put() to use this instead to cut down on code re-use? if so then we'd need to test this on PHP4. or maybe we create a new release of phpseclib: phpseclib 1.1.0 and 2.1.0
// implement $length for write() method
// benchmark this for uploading a 1GB file vs current method


class Net_SFTP_Handle
{
    function __construct($sftp, $handle)
    {
        $this->sftp = $sftp;
        $this->handle = $handle;
        $this->pos = 0; // for some modes it should be at the end - not the beginning. eg. 'a' and 'a+'
    }

    function seek($offset, $whence)
    {
        $this->pos = $offset;
    }

    function tell()
    {
        return $this->pos;
    }

    function read($length)
    {
        $sftp = $this->sftp;
        $pos = &$this->pos;
        $handle = $this->handle;

        $read = 0;
        $content = '';
        while (true) {
            $i = 0;

            while ($i < NET_SFTP_QUEUE_SIZE && ($length < 0 || $read < $length)) {
                $pos+= $read;

                $packet_size = $length > 0 ? min($sftp->max_sftp_packet, $length - $read) : $sftp->max_sftp_packet;

                $packet = pack('Na*N3', strlen($this->handle), $this->handle, $pos / 4294967296, $pos, $packet_size);
                if (!$sftp->_send_sftp_packet(NET_SFTP_READ, $packet, $i)) {
                    return false;
                }
                $packet = null;
                $read+= $packet_size;
                $i++;
            }

            if (!$i) {
                break;
            }

            $packets_sent = $i - 1;

            $clear_responses = false;
            while ($i > 0) {
                $i--;

                if ($clear_responses) {
                    $sftp->_get_sftp_packet($packets_sent - $i);
                    continue;
                } else {
                    $response = $sftp->_get_sftp_packet($packets_sent - $i);
                }

                switch ($sftp->packet_type) {
                    case NET_SFTP_DATA:
                        $temp = substr($response, 4);
                        $pos+= strlen($temp);
                        $content.= $temp;
                        $temp = null;
                        break;
                    case NET_SFTP_STATUS:
                        // could, in theory, return false if !strlen($content) but we'll hold off for the time being
                        $sftp->_logError($response);
                        $clear_responses = true; // don't break out of the loop yet, so we can read the remaining responses
                        break;
                    default:
                        user_error('Expected SSH_FX_DATA or SSH_FXP_STATUS');
                }
                $response = null;
            }

            if ($clear_responses) {
                break;
            }
        }

        if (!$sftp->_close_handle($this->handle)) {
            return false;
        }

        return $content;
    }

    function write($string)
    {
        $sftp = $this->sftp;
        $handle = $this->handle;
        $offset = &$this->pos;

        $sent = 0;
        $size = strlen($string);

        $sftp_packet_size = 4096; // PuTTY uses 4096
        // make the SFTP packet be exactly 4096 bytes by including the bytes in the NET_SFTP_WRITE packets "header"
        $sftp_packet_size-= strlen($handle) + 25;
        $i = $j = 0;
        while ($sent < $size) {
            $temp = substr($string, $sent, $sftp_packet_size);
            if ($temp === '') {
                break;
            }

            $subtemp = $offset + $sent;
            $packet = pack('Na*N3a*', strlen($handle), $handle, $subtemp / 4294967296, $subtemp, strlen($temp), $temp);
            if (!$sftp->_send_sftp_packet(NET_SFTP_WRITE, $packet, $j)) {
                return false;
            }
            $sent+= strlen($temp);

            $i++;
            $j++;

            if ($i == NET_SFTP_UPLOAD_QUEUE_SIZE) {
                if (!$sftp->_read_put_responses($i)) {
                    $i = 0;
                    break;
                }
                $i = 0;
            }
        }

        if (!$sftp->_read_put_responses($i)) {
            $sftp->_close_handle($handle);
            return false;
        }

        return strlen($string);
    }
}