export interface User { id: string; username: string; role: 'judge' | 'admin' }
export interface Device {
  mac: string; ip: string; name: string; label: string; type: string;
  simulated: boolean; risk: number; band: 'low' | 'medium' | 'high';
  confidence: string; reasons: string[]; status: string; last_seen: string;
}
export interface NetworkEvent {
  id: string; mac: string; ts: string; kind: string; evidence: Record<string, unknown>;
  actions_taken: string[]; would_have: string[]; source: 'agent' | 'simulator';
  explanation: { plain_language: string; recommended_next_step: string };
  explanation_status: 'pending' | 'ready' | 'template';
}
export interface StorageStatus { mode: 'memory' | 'postgres' }
export interface AuditEntry {
  id: string; ts: string; actor: string; action: string;
  mac?: string; command_id?: string; event_id?: string; outcome: 'requested' | 'applied' | 'failed' | 'would_have';
}
