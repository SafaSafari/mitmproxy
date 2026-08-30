import * as React from "react";
import { ModeToggle } from "./ModeToggle";
import { useAppDispatch, useAppSelector } from "../../ducks";
import type { CaptureMethod, HotspotState } from "../../modes/hotspot";
import { getSpec } from "../../modes/hotspot";
import {
    setActive,
    setCapture,
    setListenHost,
    setListenPort,
    setPassword,
    setSsid,
} from "../../ducks/modes/hotspot";
import { Popover } from "./Popover";
import ValueEditor from "../editors/ValueEditor";
import type { ServerInfo } from "../../ducks/backendState";
import { ServerStatus } from "./CaptureSetup";

export default function Hotspot() {
    const serverState = useAppSelector((state) => state.modes.hotspot);
    const backendState = useAppSelector((state) => state.backendState.servers);

    const servers = serverState.map((server) => (
        <HotspotRow
            key={server.ui_id}
            server={server}
            backendState={backendState[getSpec(server)]}
        />
    ));

    return (
        <div>
            <h4 className="mode-title">Wi-Fi Hotspot</h4>
            <p className="mode-description">
                Create a Wi-Fi access point and intercept everything its clients
                send. Useful for devices that cannot be pointed at a proxy.
            </p>
            {servers}
        </div>
    );
}

function HotspotRow({
    server,
    backendState,
}: {
    server: HotspotState;
    backendState?: ServerInfo;
}) {
    const dispatch = useAppDispatch();

    const error = server.error || backendState?.last_exception || undefined;

    return (
        <div>
            <ModeToggle
                value={server.active}
                label="Run Wi-Fi Hotspot"
                onChange={() =>
                    dispatch(setActive({ server, value: !server.active }))
                }
            >
                <Popover icon="settings">
                    <h4>Advanced Configuration</h4>
                    <p>Network Name (SSID)</p>
                    <ValueEditor
                        className="mode-input"
                        content={server.ssid || ""}
                        placeholder="mitmproxy"
                        onEditDone={(ssid) =>
                            dispatch(setSsid({ server, value: ssid }))
                        }
                    />
                    <p>Password</p>
                    <ValueEditor
                        className="mode-input"
                        content={server.password ?? ""}
                        placeholder="mitmproxy"
                        onEditDone={(password) =>
                            dispatch(setPassword({ server, value: password }))
                        }
                    />
                    <p>Capture Method</p>
                    <select
                        className="mode-input"
                        value={server.capture ?? "auto"}
                        onChange={(e) =>
                            dispatch(
                                setCapture({
                                    server,
                                    value: e.target.value as CaptureMethod,
                                }),
                            )
                        }
                    >
                        <option value="auto">Automatic</option>
                        <option value="tun">
                            TUN interface (TCP + UDP, Linux only)
                        </option>
                        <option value="redirect">
                            Packet filter redirect (TCP only)
                        </option>
                    </select>
                    <p>Listen Host</p>
                    <ValueEditor
                        className="mode-input"
                        content={server.listen_host || ""}
                        placeholder="(all interfaces)"
                        onEditDone={(host) =>
                            dispatch(setListenHost({ server, value: host }))
                        }
                    />
                    <p>Listen Port</p>
                    <ValueEditor
                        className="mode-input"
                        content={
                            server.listen_port
                                ? server.listen_port.toString()
                                : ""
                        }
                        placeholder="8080 (unused with a TUN interface)"
                        onEditDone={(port) =>
                            dispatch(
                                setListenPort({
                                    server,
                                    value: parseInt(port),
                                }),
                            )
                        }
                    />
                </Popover>
            </ModeToggle>
            <ServerStatus error={error} backendState={backendState} />
        </div>
    );
}
