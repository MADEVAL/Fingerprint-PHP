<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Collector;

use GlobusStudio\Fingerprint\Configuration\FingerprintConfig;
use GlobusStudio\Fingerprint\Request\RequestContext;
use GlobusStudio\Fingerprint\Signal\Signal;
use GlobusStudio\Fingerprint\Signal\SignalSensitivity;
use GlobusStudio\Fingerprint\Signal\SignalSet;
use GlobusStudio\Fingerprint\Signal\SignalStability;
use GlobusStudio\Fingerprint\Signal\SignalType;

final class TlsSignalCollector implements SignalCollectorInterface
{
    public function collect(RequestContext $request, FingerprintConfig $config): SignalSet
    {
        $signals = new SignalSet();
        $server = $request->server();

        $sslProtocol = $server->string('SSL_PROTOCOL');
        if ($sslProtocol !== '') {
            $signals->add(new Signal('tls.protocol', SignalType::Tls, $sslProtocol, $sslProtocol, $config->weightFor('tls.protocol'), SignalStability::Medium, SignalSensitivity::Low, 'server.SSL_PROTOCOL'));
        }

        $sslCipher = $server->string('SSL_CIPHER');
        if ($sslCipher !== '') {
            $signals->add(new Signal('tls.cipher', SignalType::Tls, $sslCipher, $sslCipher, 1, SignalStability::Medium, SignalSensitivity::Low, 'server.SSL_CIPHER', false, 'context_only'));
        }

        foreach (['SSL_CLIENT_VERIFY', 'SSL_CLIENT_S_DN', 'SSL_CLIENT_I_DN', 'SSL_CLIENT_M_SERIAL'] as $serverKey) {
            $value = $server->string($serverKey);
            if ($value === '') {
                continue;
            }

            $signals->add(new Signal('tls.' . strtolower($serverKey), SignalType::Tls, $value, hash('sha256', $value), 0, SignalStability::Stable, SignalSensitivity::Special, 'server.' . $serverKey, false, 'client_certificate_data_disabled'));
        }

        return $signals;
    }
}
