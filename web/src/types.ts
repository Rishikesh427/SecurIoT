export interface User { id: string; username: string; role: string }
export interface Device {
  mac: string; ip: string; name: string; label: string; type: string;
  simulated: boolean; risk: number; band: 'low' | 'medium' | 'high';
  confidence: string; reasons: string[]; status: string; last_seen: string;
}
export interface NetworkEvent {
  id: string; mac: string; ts: string; kind: string; evidence: Record<string, unknown>;
  actions_taken: string[]; would_have: string[]; source: 'agent' | 'simulator';
}
export interface StorageStatus { mode: 'memory' | 'postgres' }
