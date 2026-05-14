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

final class ServerSignalCollector implements SignalCollectorInterface
{
    public function collect(RequestContext $request, FingerprintConfig $config): SignalSet
    {
        $signals = new SignalSet();
        $server = $request->server();
        $isHttps = in_array(strtolower($server->string('HTTPS')), ['on', '1'], true) || strtolower($server->string('REQUEST_SCHEME')) === 'https' || $server->string('SERVER_PORT') === '443';

        $signals->add(new Signal('server.software', SignalType::Server, $server->string('SERVER_SOFTWARE'), $this->coarseServerSoftware($server->string('SERVER_SOFTWARE')), 0, SignalStability::Stable, SignalSensitivity::Low, 'server.SERVER_SOFTWARE', false, 'environment_only'));
        $signals->add(new Signal('server.protocol', SignalType::Server, $request->protocol(), $request->protocol(), 0, SignalStability::Medium, SignalSensitivity::Low, 'server.SERVER_PROTOCOL', false, 'environment_only'));
        $signals->add(new Signal('server.gateway_interface', SignalType::Server, $server->string('GATEWAY_INTERFACE'), $server->string('GATEWAY_INTERFACE'), 0, SignalStability::Stable, SignalSensitivity::Low, 'server.GATEWAY_INTERFACE', false, 'environment_only'));
        $signals->add(new Signal('request.method', SignalType::Server, $request->method(), $request->method(), 0, SignalStability::Volatile, SignalSensitivity::Low, 'server.REQUEST_METHOD', false, 'request_context_only'));
        $signals->add(new Signal('request.uri_shape', SignalType::Server, $request->uri(), parse_url($request->uri(), PHP_URL_PATH) ?: '/', 0, SignalStability::Volatile, SignalSensitivity::Medium, 'server.REQUEST_URI', false, 'request_context_only'));
        $signals->add(new Signal('server.sapi', SignalType::Server, $request->sapi(), $request->sapi(), 0, SignalStability::Stable, SignalSensitivity::Low, 'php_sapi_name', false, 'environment_only'));
        $signals->add(new Signal('server.is_https', SignalType::Server, $isHttps, $isHttps, 0, SignalStability::Medium, SignalSensitivity::Low, 'server.HTTPS', false, 'environment_only'));

        return $signals;
    }

    private function coarseServerSoftware(string $serverSoftware): string
    {
        return match (true) {
            stripos($serverSoftware, 'nginx') !== false => 'nginx',
            stripos($serverSoftware, 'apache') !== false => 'apache',
            stripos($serverSoftware, 'iis') !== false => 'iis',
            stripos($serverSoftware, 'caddy') !== false => 'caddy',
            stripos($serverSoftware, 'litespeed') !== false => 'litespeed',
            $serverSoftware === '' => 'unknown',
            default => 'other',
        };
    }
}
