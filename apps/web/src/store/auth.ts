import { create } from "zustand";
import { persist } from "zustand/middleware";

export interface User {
  id: string;
  org_id: string | null;
  email: string;
  name: string;
  role: string;
  status: string;
}

interface AuthState {
  accessToken: string | null;
  refresh: string | null;
  user: User | null;
  setTokens: (access: string, refresh: string) => void;
  setUser: (user: User) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      accessToken: null,
      refresh: null,
      user: null,
      setTokens: (accessToken, refresh) => set({ accessToken, refresh }),
      setUser: (user) => set({ user }),
      logout: () => set({ accessToken: null, refresh: null, user: null }),
    }),
    { name: "sentinelx-auth" },
  ),
);
