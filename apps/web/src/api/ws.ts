import { useEffect } from "react";
import { useAuthStore } from "../store/auth";
import { useLiveStore } from "../store/live";

export function useRealtime() {
  const token = useAuthStore((s) => s.accessToken);

  useEffect(() => {
    if (!token) return;
    let ws: WebSocket | null = null;
    let retry = 0;
    let closed = false;

    const connect = () => {
      const proto = location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${location.host}/ws/events`);
      ws.onopen = () => {
        ws?.send(JSON.stringify({ token }));
        retry = 0;
        useLiveStore.getState().setConnected(true);
      };
      ws.onmessage = (msg) => {
        try {
          const data = JSON.parse(msg.data);
          useLiveStore.getState().push(data);
        } catch {
          /* ignore */
        }
      };
      ws.onclose = () => {
        useLiveStore.getState().setConnected(false);
        if (!closed && retry < 5) {
          retry += 1;
          setTimeout(connect, 1000 * retry);
        }
      };
    };
    connect();
    return () => {
      closed = true;
      ws?.close();
    };
  }, [token]);
}
