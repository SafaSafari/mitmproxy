import * as React from "react";
import { useEffect, useRef } from "react";
import type { HotspotInfo, ServerInfo } from "../../ducks/backendState";
import { formatAddress } from "../../utils";
import QRCode from "qrcode";

export default function CaptureSetup() {
    return (
        <div className="capture-setup" style={{ padding: "1em 2em" }}>
            <h3>mitmproxy is running.</h3>
            <p>
                No flows have been recorded yet.
                <br />
                To start capturing traffic, please configure your settings in
                the Capture tab.
            </p>
        </div>
    );
}

function ServerDescription({
    description,
    listen_addrs,
    is_running,
    wireguard_conf,
    hotspot,
    type,
}: ServerInfo) {
    const qrCode = useRef(null);
    useEffect(() => {
        if (wireguard_conf && qrCode.current)
            QRCode.toCanvas(qrCode.current, wireguard_conf, {
                margin: 0,
                scale: 3,
            });
    }, [wireguard_conf]);

    let listen_str;
    const all_same_port =
        listen_addrs.length === 1 ||
        (listen_addrs.length === 2 &&
            listen_addrs[0][1] === listen_addrs[1][1]);
    const unbound = listen_addrs.every((addr) =>
        ["::", "0.0.0.0"].includes(addr[0]),
    );
    if (all_same_port && unbound) {
        listen_str = formatAddress(["*", listen_addrs[0][1]]);
    } else {
        listen_str = listen_addrs.map(formatAddress).join(" and ");
    }
    description = description[0].toUpperCase() + description.substr(1);
    let desc;
    if (!is_running) {
        desc = (
            <>
                <div className="text-warning">{description} starting...</div>
            </>
        );
    } else {
        desc = (
            <>
                {/* modes without a listener -- local, tun, hotspot -- have no address to show. */}
                {type === "local" || listen_addrs.length === 0 ? (
                    <div className="text-success">{description} is active.</div>
                ) : (
                    <div className="text-success">
                        {description} listening at {listen_str}.
                    </div>
                )}
                {wireguard_conf && (
                    <div className="wireguard-config">
                        <pre>{wireguard_conf}</pre>
                        <canvas ref={qrCode} />
                    </div>
                )}
                {hotspot && <HotspotDetails {...hotspot} />}
            </>
        );
    }
    return <div>{desc}</div>;
}

/** The credentials and capture method of a running hotspot, plus a QR code to join it. */
function HotspotDetails({
    ssid,
    password,
    interface: iface,
    band,
    address,
    capture,
    redirector,
}: HotspotInfo) {
    const qrCode = useRef(null);
    useEffect(() => {
        if (!qrCode.current) return;
        // the Wi-Fi network provisioning format that phone cameras understand.
        const escape = (s: string) => s.replace(/([\\;,":])/g, "\\$1");
        const auth = password ? "WPA" : "nopass";
        QRCode.toCanvas(
            qrCode.current,
            `WIFI:T:${auth};S:${escape(ssid)};P:${escape(password ?? "")};;`,
            { margin: 0, scale: 3 },
        );
    }, [ssid, password]);

    return (
        <div className="wireguard-config">
            <dl className="hotspot-details">
                <dt>Network</dt>
                <dd>{ssid}</dd>
                {password && (
                    <>
                        <dt>Password</dt>
                        <dd>{password}</dd>
                    </>
                )}
                <dt>Interface</dt>
                <dd>
                    {iface}
                    {band && ` (${band === "a" ? "5 GHz" : "2.4 GHz"})`}
                </dd>
                {address && (
                    <>
                        <dt>Gateway</dt>
                        <dd>{address}</dd>
                    </>
                )}
                <dt>Capture</dt>
                <dd>
                    {redirector
                        ? `${capture} (${redirector})`
                        : "not intercepted"}
                </dd>
            </dl>
            <canvas ref={qrCode} />
        </div>
    );
}

export function ServerStatus({
    error,
    backendState,
}: {
    error?: string;
    backendState?: ServerInfo;
}) {
    return (
        <div className="mode-status">
            {error ? (
                <div className="text-danger">{error}</div>
            ) : (
                backendState && <ServerDescription {...backendState} />
            )}
        </div>
    );
}
