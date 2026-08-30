import hotspotReducer, {
    initialState,
    setActive,
    setCapture,
    setListenHost,
    setListenPort,
    setPassword,
    setSsid,
} from "./../../../ducks/modes/hotspot";
import { getSpec, parseRaw, splitOptions } from "../../../modes/hotspot";
import { STATE_UPDATE } from "../../../ducks/backendState";
import { TStore } from "../tutils";
import fetchMock, { enableFetchMocks } from "jest-fetch-mock";

describe("hotspotSlice", () => {
    it("should have working setters", async () => {
        enableFetchMocks();
        const store = TStore();

        expect(store.getState().modes.hotspot[0]).toEqual({
            active: false,
            ui_id: store.getState().modes.hotspot[0].ui_id,
        });

        const server = store.getState().modes.hotspot[0];
        await store.dispatch(setActive({ value: false, server }));
        await store.dispatch(setListenHost({ value: "127.0.0.1", server }));
        await store.dispatch(setListenPort({ value: 4444, server }));
        await store.dispatch(setSsid({ value: "my-network", server }));
        await store.dispatch(setPassword({ value: "hunter22", server }));
        await store.dispatch(setCapture({ value: "redirect", server }));

        expect(store.getState().modes.hotspot[0]).toEqual({
            active: false,
            listen_host: "127.0.0.1",
            listen_port: 4444,
            ssid: "my-network",
            password: "hunter22",
            capture: "redirect",
            ui_id: store.getState().modes.hotspot[0].ui_id,
        });

        expect(fetchMock).toHaveBeenCalledTimes(6);
    });

    it("should handle errors", async () => {
        fetchMock.mockReject(new Error("invalid spec"));
        const store = TStore();

        const server = store.getState().modes.hotspot[0];
        await store.dispatch(setSsid({ value: "my-network", server }));

        expect(fetchMock).toHaveBeenCalled();
        expect(store.getState().modes.hotspot[0].error).toBe("invalid spec");
    });

    it("should handle RECEIVE_STATE with an active hotspot", () => {
        const action = STATE_UPDATE({
            servers: {
                "hotspot:ssid=my-network,password=hunter22": {
                    description: "Wi-Fi hotspot (my-network)",
                    full_spec: "hotspot:ssid=my-network,password=hunter22",
                    is_running: true,
                    last_exception: null,
                    listen_addrs: [],
                    type: "hotspot",
                },
            },
        });
        const newState = hotspotReducer(initialState, action);
        expect(newState).toEqual([
            {
                active: true,
                ssid: "my-network",
                password: "hunter22",
                listen_host: undefined,
                listen_port: undefined,
                ui_id: newState[0].ui_id,
            },
        ]);
    });

    it("should handle RECEIVE_STATE with no active hotspot", () => {
        const action = STATE_UPDATE({ servers: {} });
        const newState = hotspotReducer(initialState, action);
        expect(newState).toEqual([
            {
                active: false,
                ui_id: newState[0].ui_id,
            },
        ]);
    });
});

describe("hotspot spec", () => {
    it("should build a spec", () => {
        expect(getSpec({ active: true })).toBe("hotspot");
        expect(getSpec({ active: true, ssid: "net" })).toBe("hotspot:ssid=net");
        expect(
            getSpec({
                active: true,
                ssid: "net",
                password: "hunter22",
                capture: "tun",
                listen_port: 8081,
            }),
        ).toBe("hotspot:ssid=net,password=hunter22,capture=tun@8081");
    });

    it("should omit the default capture method", () => {
        expect(getSpec({ active: true, capture: "auto" })).toBe("hotspot");
    });

    it("should keep an empty password, which means an open network", () => {
        expect(getSpec({ active: true, password: "" })).toBe(
            "hotspot:password=",
        );
    });

    it("should round-trip options the UI does not expose", () => {
        const spec = "hotspot:ssid=net,iface=wlan0,band=a";
        const state = parseRaw({
            full_spec: spec,
            name: "hotspot",
            data: spec.slice(8),
        });
        expect(state.ssid).toBe("net");
        expect(state.extra).toBe("iface=wlan0,band=a");
        expect(getSpec(state)).toBe("hotspot:ssid=net,iface=wlan0,band=a");
    });

    it("should treat bare data as an SSID", () => {
        expect(
            parseRaw({
                full_spec: "hotspot:my-network",
                name: "hotspot",
                data: "my-network",
            }).ssid,
        ).toBe("my-network");
    });

    it("should keep commas that belong to a value", () => {
        // `network` is not an option name, so it stays part of the SSID.
        expect(splitOptions("ssid=my,network,band=a")).toEqual([
            "ssid=my,network",
            "band=a",
        ]);
        expect(
            parseRaw({
                full_spec: "",
                name: "hotspot",
                data: "ssid=my,network",
            }).ssid,
        ).toBe("my,network");
    });
});
