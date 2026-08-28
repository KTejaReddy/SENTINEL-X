import { create } from "zustand";

export interface LiveEvent {
  id: string;
  type: string;
  payload: any;
  ts: string;
}

interface LiveState {
  connected: boolean;
  events: LiveEvent[];
  push: (ev: LiveEvent) => void;
  setConnected: (connected: boolean) => void;
}

export const useLiveStore = create<LiveState>((set) => ({
  connected: false,
  events: [],
  push: (ev) =>
    set((s) => ({ events: [ev, ...s.events].slice(0, 200) })),
  setConnected: (connected) => set({ connected }),
}));
