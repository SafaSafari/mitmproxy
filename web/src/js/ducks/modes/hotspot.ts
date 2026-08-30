import type { CaptureMethod, HotspotState } from "../../modes/hotspot";
import { parseRaw } from "../../modes/hotspot";
import { STATE_RECEIVE, STATE_UPDATE } from "../backendState";
import { addSetter, createModeUpdateThunk, updateState } from "./utils";
import { createSlice } from "@reduxjs/toolkit";

export const setActive = createModeUpdateThunk<boolean>(
    "modes/hotspot/setActive",
);
export const setListenHost = createModeUpdateThunk<string | undefined>(
    "modes/hotspot/setListenHost",
);
export const setListenPort = createModeUpdateThunk<number | undefined>(
    "modes/hotspot/setListenPort",
);
export const setSsid = createModeUpdateThunk<string | undefined>(
    "modes/hotspot/setSsid",
);
export const setPassword = createModeUpdateThunk<string | undefined>(
    "modes/hotspot/setPassword",
);
export const setCapture = createModeUpdateThunk<CaptureMethod | undefined>(
    "modes/hotspot/setCapture",
);

export const initialState: HotspotState[] = [
    {
        active: false,
        ui_id: Math.random(),
    },
];

export const hotspotSlice = createSlice({
    name: "modes/hotspot",
    initialState,
    reducers: {},
    extraReducers: (builder) => {
        addSetter(builder, "active", setActive);
        addSetter(builder, "listen_host", setListenHost);
        addSetter(builder, "listen_port", setListenPort);
        addSetter(builder, "ssid", setSsid);
        addSetter(builder, "password", setPassword);
        addSetter(builder, "capture", setCapture);
        builder.addCase(STATE_RECEIVE, updateState("hotspot", parseRaw));
        builder.addCase(STATE_UPDATE, updateState("hotspot", parseRaw));
    },
});

export default hotspotSlice.reducer;
