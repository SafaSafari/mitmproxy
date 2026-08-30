import type { ModeState, RawSpecParts } from ".";
import { includeListenAddress } from ".";

export type CaptureMethod = "auto" | "tun" | "redirect";

export interface HotspotState extends ModeState {
    ssid?: string;
    password?: string;
    capture?: CaptureMethod;
    /**
     * Options this UI does not expose (iface, band, backend, ...), kept verbatim.
     *
     * Without this, toggling any control here would silently drop the rest of a
     * spec that was passed on the command line.
     */
    extra?: string;
}

/**
 * Every option name the backend understands, see mitmproxy/hotspot/base.py.
 *
 * We need them to tell `ssid=my,network` (one option) apart from
 * `ssid=foo,band=a` (two), the same way the backend does.
 */
const OPTION_NAMES = [
    "ssid",
    "password",
    "pass",
    "iface",
    "interface",
    "share",
    "uplink",
    "gateway",
    "gw",
    "band",
    "capture",
    "tun",
    "backend",
    "sudo",
    "redirect",
    "quic",
];

export const splitOptions = (data: string): string[] => {
    const parts: string[] = [];
    for (const chunk of data.split(",")) {
        const key = chunk.split("=")[0].trim().toLowerCase();
        if (
            parts.length > 0 &&
            (!chunk.includes("=") || !OPTION_NAMES.includes(key))
        ) {
            parts[parts.length - 1] += `,${chunk}`;
        } else {
            parts.push(chunk);
        }
    }
    return parts;
};

export const getSpec = (s: HotspotState): string => {
    const options: string[] = [];
    if (s.ssid) options.push(`ssid=${s.ssid}`);
    if (s.password !== undefined) options.push(`password=${s.password}`);
    if (s.capture && s.capture !== "auto") options.push(`capture=${s.capture}`);
    if (s.extra) options.push(s.extra);

    const modeNameAndData = options.length
        ? `hotspot:${options.join(",")}`
        : "hotspot";
    return includeListenAddress(modeNameAndData, s);
};

export const parseRaw = ({
    data,
    listen_host,
    listen_port,
}: RawSpecParts): HotspotState => {
    const state: HotspotState = {
        ui_id: Math.random(),
        active: true,
        listen_host,
        listen_port,
    };
    if (!data) {
        return state;
    }
    if (!data.includes("=")) {
        // `hotspot:my-network` is shorthand for `hotspot:ssid=my-network`.
        return { ...state, ssid: data };
    }

    const extra: string[] = [];
    for (const part of splitOptions(data)) {
        const idx = part.indexOf("=");
        const key = part.slice(0, idx).trim().toLowerCase();
        const value = part.slice(idx + 1).trim();
        switch (key) {
            case "ssid":
                state.ssid = value;
                break;
            case "password":
            case "pass":
                state.password = value;
                break;
            case "capture":
                state.capture = value as CaptureMethod;
                break;
            default:
                extra.push(part.trim());
        }
    }
    if (extra.length > 0) {
        state.extra = extra.join(",");
    }
    return state;
};
