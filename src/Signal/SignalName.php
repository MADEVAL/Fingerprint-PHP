<?php

declare(strict_types=1);

namespace GlobusStudio\Fingerprint\Signal;

final class SignalName
{
    public const BrowserFamily = 'browser.family';
    public const BrowserMajor = 'browser.major';
    public const BrowserEngine = 'browser.engine';
    public const OsFamily = 'os.family';
    public const OsMajor = 'os.major';
    public const DeviceClass = 'device.class';
    public const HeaderAccept = 'header.accept';
    public const HeaderAcceptLanguage = 'header.accept_language';
    public const HeaderAcceptEncoding = 'header.accept_encoding';
    public const HeaderOrderHash = 'header.order_hash';
    public const IpPrefix = 'ip.prefix';
    public const IpFull = 'ip.full';
    public const ProxyChainShape = 'proxy.chain_shape';
}
