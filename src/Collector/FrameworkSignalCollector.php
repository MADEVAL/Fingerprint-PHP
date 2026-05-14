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

final class FrameworkSignalCollector implements SignalCollectorInterface
{
    public function collect(RequestContext $request, FingerprintConfig $config): SignalSet
    {
        $signals = new SignalSet();
        $framework = $this->detectFramework($request);
        $runtime = $this->detectRuntime($request);

        if ($framework !== null) {
            $signals->add(new Signal('framework.name', SignalType::Framework, $framework, $framework, 0, SignalStability::Stable, SignalSensitivity::Low, 'framework.detection', false, 'environment_only'));
        }

        if ($runtime !== null) {
            $signals->add(new Signal('framework.runtime', SignalType::Framework, $runtime, $runtime, 0, SignalStability::Stable, SignalSensitivity::Low, 'runtime.detection', false, 'environment_only'));
        }

        return $signals;
    }

    private function detectFramework(RequestContext $request): ?string
    {
        $server = $request->server();

        if ($server->has('LARAVEL_START') || $server->has('HTTP_X_LARAVEL_SESSION')) {
            return 'laravel';
        }

        if ($server->has('SYMFONY_DOTENV_VARS') || str_contains(strtolower($server->string('APP_RUNTIME')), 'symfony')) {
            return 'symfony';
        }

        if ($server->has('LAMINAS_ENV') || $server->has('HTTP_X_LAMINAS_REQUEST')) {
            return 'laminas';
        }

        if ($server->has('SLIM_MODE') || $server->has('HTTP_X_SLIM_REQUEST')) {
            return 'slim';
        }

        return null;
    }

    private function detectRuntime(RequestContext $request): ?string
    {
        $server = $request->server();
        $serverSoftware = strtolower($server->string('SERVER_SOFTWARE'));

        if (str_contains($serverSoftware, 'frankenphp') || $server->has('FRANKENPHP_CONFIG')) {
            return 'frankenphp';
        }

        if ($server->has('RR_MODE') || str_contains($serverSoftware, 'roadrunner')) {
            return 'roadrunner';
        }

        if ($server->has('SWOOLE_HTTP_HOST') || str_contains($serverSoftware, 'swoole')) {
            return 'swoole';
        }

        return null;
    }
}
