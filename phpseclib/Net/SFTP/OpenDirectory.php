<?php

namespace phpseclib4\Net\SFTP;

use phpseclib4\Net\SFTP;
use phpseclib4\Common\Functions\Strings;
use phpseclib4\Exception\UnexpectedValueException;
use phpseclib4\Net\SFTP\PacketType as SFTPPacketType;

class OpenDirectory
{
    private array $files = [];
    private int $count = 0;

    public function __construct(private SFTP $sftp, private string $path, private int $channel, private string $handle)
    {
    }

    public function read()
    {
        if ($this->count < count($this->files)) {
            return $this->files[$this->count++];
        }
        $read = function(int $channel, string $handle): array {
            $this->send_sftp_packet($channel, SFTPPacketType::READDIR, Strings::packSSH2('s', $handle));
            $response = $this->get_sftp_packet($channel);
            switch ($this->packet_type) {
                case SFTPPacketType::NAME:
                    $result = [];
                    [$count] = Strings::unpackSSH2('N', $response);
                    for ($i = 0; $i < $count; $i++) {
                        [$shortname] = Strings::unpackSSH2('s', $response);
                        // SFTPv4 "removed the long filename from the names structure-- it can now be
                        //         built from information available in the attrs structure."
                        if ($this->version[$channel] < 4) {
                            [$longname] = Strings::unpackSSH2('s', $response);
                        }
                        $attributes = self::parseAttributes($this->version[$channel], $response);
                        if (!isset($attributes['type']) && $this->version[$channel] < 4) {
                            $fileType = self::parseLongname($longname);
                            if ($fileType) {
                                $attributes['type'] = $fileType;
                            }
                        }
                        $result[] = $shortname;

                        // SFTPv6 has an optional boolean end-of-list field, but we'll ignore that, since the
                        // final SSH_FXP_STATUS packet should tell us that, already.
                    }
                    return $result;
                case SFTPPacketType::STATUS:
                    [$status] = Strings::unpackSSH2('N', $response);
                    throw $this->throwStatusError($response, $status);
                default:
                    throw new UnexpectedValueException(
                        'Expected PacketType::NAME or PacketType::STATUS. '
                        . 'Got packet type: ' . SFTPPacketType::getConstantNameByValue($this->packet_type)
                    );
            }
        };
        
        $this->files = $read->call($this->sftp, $this->channel, $this->handle);
        $this->count = 1;

        return $this->files[0];
    }
}