export type Kind = 'http' | 'command' | 'browser';
export type Action = {
  name: string;
  kind: Kind;
  description: string;
  destination: string;
  secrets: number;
  timeout: number;
  grants: number;
};
export type Client = {
  name: string;
  actions: string[];
  expiresAt?: number | null;
  expired?: boolean;
};
export type Event = { id: string; time: string; client: string; action: string; status: string };
export type Snapshot = {
  initialized: boolean;
  online: boolean;
  email: string;
  region: string;
  port: number;
  actions: Action[];
  clients: Client[];
  events: Event[];
  pendingRestart: boolean;
  statePath: string;
};
export type PolicyAction = {
  kind: Kind;
  description?: string;
  secrets?: Record<string, { record: string; field: string; transform?: string }>;
  timeout?: number;
  [key: string]: unknown;
};
export const emptySnapshot = (): Snapshot => ({
  initialized: false,
  online: false,
  email: '',
  region: 'US',
  port: 19463,
  actions: [],
  clients: [],
  events: [],
  pendingRestart: false,
  statePath: '',
});
