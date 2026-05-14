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

final class CookieSignalCollector implements SignalCollectorInterface
{
    public function collect(RequestContext $request, FingerprintConfig $config): SignalSet
    {
        $signals = new SignalSet();

        foreach ($config->cookieModes() as $cookieName => $mode) {
            $value = $request->cookies()->get($cookieName);
            $present = $value !== null;
            $source = 'cookie.' . $cookieName;

            if ($mode === 'presence') {
                $signals->add(new Signal('cookie.' . $cookieName . '.presence', SignalType::Cookie, $present, $present, $config->weightFor('cookie.allowlisted_presence'), SignalStability::Medium, SignalSensitivity::High, $source, true, 'allowlisted_cookie_presence'));
                continue;
            }

            if (!$present) {
                continue;
            }

            if ($mode === 'hash') {
                $hashedValue = hash_hmac('sha256', (string) $value, $config->hashingConfig()->secret());
                $signals->add(new Signal('cookie.' . $cookieName . '.hash', SignalType::Cookie, null, $hashedValue, 2, SignalStability::Medium, SignalSensitivity::High, $source, true, 'allowlisted_cookie_hash'));
                continue;
            }

            if ($mode === 'normalized') {
                $signals->add(new Signal('cookie.' . $cookieName . '.normalized', SignalType::Cookie, null, trim((string) $value), 1, SignalStability::Medium, SignalSensitivity::High, $source, true, 'allowlisted_cookie_normalized'));
            }
        }

        return $signals;
    }
}
