import { useCallback, useEffect, useState } from 'react';

import { createActiveRecurrence, createIdempotencyKey, deleteActiveRecurrence, listActiveRecurrences, pauseActiveRecurrence, resumeActiveRecurrence } from './api';
import type { ActiveAsset, ActiveAssetVerification, ActiveCapability, ActiveRecurrence } from './types';

const LABELS: Record<ActiveCapability, string> = {
  active_nmap_basic: 'TCP exposure',
  active_dns_inventory: 'DNS inventory',
  active_dns_osint: 'DNS public signals',
  active_http_basic_header_review: 'HTTP headers',
  active_tls_basic: 'TLS summary',
};
const WEEKDAYS = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'] as const;

export function ActiveRecurrencePanel({ asset, verification, canManage }: { asset: ActiveAsset; verification: ActiveAssetVerification | null; canManage: boolean }) {
  const [items, setItems] = useState<ActiveRecurrence[]>([]);
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [capability, setCapability] = useState<ActiveCapability>(asset.capabilities[0]);
  const [port, setPort] = useState<number | ''>(asset.allowed_ports[0] ?? '');
  const [intervalDays, setIntervalDays] = useState<7 | 14 | 30>(7);
  const [timezoneName, setTimezoneName] = useState(() => Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC');
  const [windowWeekday, setWindowWeekday] = useState<(typeof WEEKDAYS)[number]>(() => WEEKDAYS[(new Date().getDay() + 6) % 7]);
  const [windowStartHour, setWindowStartHour] = useState(() => Math.min(new Date().getHours(), 22));
  const [windowDurationHours, setWindowDurationHours] = useState<1 | 2 | 4 | 8>(2);
  const [confirmed, setConfirmed] = useState(false);
  const [deleteConfirmed, setDeleteConfirmed] = useState<Record<string, boolean>>({});

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const response = await listActiveRecurrences(asset.id);
      if (!response || typeof response.enabled !== 'boolean' || !Array.isArray(response.items)) {
        throw new Error('Recurring review policy returned an invalid contract.');
      }
      setItems(response.items);
      setEnabled(response.enabled);
      setError(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Recurring reviews could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, [asset.id]);

  useEffect(() => { void refresh(); }, [refresh]);

  async function create() {
    setBusyId('create'); setError(null); setNotice(null);
    try {
      await createActiveRecurrence(asset.id, {
        capability,
        ...(capability === 'active_tls_basic' && typeof port === 'number' ? { port } : {}),
        interval_days: intervalDays,
        timezone_name: timezoneName.trim(),
        window_weekdays: [windowWeekday],
        window_start_hour: windowStartHour,
        window_duration_hours: windowDurationHours,
        recurrence_confirmed: true,
        idempotency_key: createIdempotencyKey(),
      });
      setConfirmed(false);
      setNotice('Recurring review scheduled against the current authorization and verification.');
      await refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'The recurring review could not be created.');
    } finally { setBusyId(null); }
  }

  async function mutate(item: ActiveRecurrence, action: 'pause' | 'resume' | 'delete') {
    setBusyId(item.id); setError(null); setNotice(null);
    try {
      if (action === 'pause') await pauseActiveRecurrence(asset.id, item);
      else if (action === 'resume') await resumeActiveRecurrence(asset.id, item);
      else await deleteActiveRecurrence(asset.id, item.id);
      setNotice(action === 'delete' ? 'Future recurring reviews removed.' : `Recurring review ${action}d.`);
      setDeleteConfirmed((current) => ({ ...current, [item.id]: false }));
      await refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'The recurring review could not be changed. Refresh and retry.');
    } finally { setBusyId(null); }
  }

  const canCreate = canManage && enabled === true && asset.status === 'active' && verification?.status === 'verified';
  const selectedPort = capability === 'active_tls_basic' && typeof port === 'number' ? port : null;
  const selectedAlreadyScheduled = items.some((item) => item.capability === capability && item.port === selectedPort);
  return <section className="active-recurrence" aria-labelledby={`active-recurrence-${asset.id}`} aria-busy={loading || busyId !== null}>
    <div className="active-form-heading">
      <div><h4 id={`active-recurrence-${asset.id}`}>Recurring authorized reviews</h4><p className="muted">Opt-in schedules run every 7, 14 or 30 elapsed UTC days. Every occurrence revalidates the exact authorization revision and current control verification.</p></div>
      {enabled !== null ? <span className={`status-pill ${enabled ? 'ok' : ''}`}>{enabled ? 'Operator enabled' : 'Operator disabled'}</span> : null}
    </div>
    {loading ? <p role="status" className="muted">Loading recurring review policy…</p> : null}
    {!loading && enabled === false ? <p className="empty-state">Recurring reviews are disabled by default. Only an operator can enable the scheduler; no future network activity is queued.</p> : null}
    {!loading && enabled && items.length === 0 ? <p className="empty-state">No recurring review is configured for this asset.</p> : null}
    {items.length ? <ul className="active-recurrence-list">{items.map((item) => <li key={item.id}>
      <div><strong>{LABELS[item.capability]}{item.port ? ` · port ${item.port}` : ''}</strong><span className={`status-pill ${item.status === 'active' ? 'ok' : ''}`}>{item.status}</span></div>
      <dl className="summary-list"><dt>Cadence</dt><dd>Every {item.interval_days} days</dd><dt>Authorized window</dt><dd>{item.window_weekdays.join(', ')} · {String(item.window_start_hour).padStart(2, '0')}:00–{String(item.window_start_hour + item.window_duration_hours).padStart(2, '0')}:00 · {item.timezone_name}</dd><dt>Next eligible run</dt><dd>{item.status === 'paused' ? 'None — resuming recalculates the next window' : item.status === 'suspended' && item.reason_code.startsWith('authorization_') ? 'None — authorization must be re-attested' : new Date(item.next_run_at).toLocaleString()}</dd><dt>Retry state</dt><dd>{item.failure_count ? `${item.last_outcome.replace(/_/g, ' ')} · attempt ${item.failure_count} · ${item.next_retry_at ? `not before ${new Date(item.next_retry_at).toLocaleString()}` : 'pending'}` : 'No deferred retry'}</dd><dt>Authorization</dt><dd>Revision {item.authorization_revision_sequence} · <code>{item.authorization_revision_id.slice(0, 12)}…</code>{item.authorization_expires_at ? ` · ends ${new Date(item.authorization_expires_at).toLocaleString()}` : ' · legacy expiry unavailable'}</dd><dt>State reason</dt><dd>{item.reason_code.replace(/_/g, ' ')}</dd></dl>
      {canManage ? <div className="active-recurrence-actions">
        {item.status === 'active' ? <button type="button" className="secondary-button" disabled={busyId === item.id} onClick={() => void mutate(item, 'pause')}>Pause future runs</button> : <button type="button" className="secondary-button" disabled={busyId === item.id || verification?.status !== 'verified' || asset.status !== 'active'} onClick={() => void mutate(item, 'resume')}>Resume with current authorization</button>}
        <label className="checkbox-row"><input type="checkbox" checked={deleteConfirmed[item.id] ?? false} onChange={(event) => setDeleteConfirmed((current) => ({ ...current, [item.id]: event.target.checked }))} />Remove this schedule permanently</label>
        <button type="button" className="danger-button" disabled={busyId === item.id || !deleteConfirmed[item.id]} onClick={() => void mutate(item, 'delete')}>Remove future runs</button>
      </div> : null}
    </li>)}</ul> : null}
    {canCreate ? <div className="active-recurrence-create">
      <label><span>Authorized capability</span><select value={capability} onChange={(event) => { setCapability(event.target.value as ActiveCapability); setConfirmed(false); }}>{asset.capabilities.map((item) => <option key={item} value={item}>{LABELS[item]}</option>)}</select></label>
      {capability === 'active_tls_basic' ? <label><span>Authorized port</span><select value={port} onChange={(event) => setPort(Number(event.target.value))}>{asset.allowed_ports.map((item) => <option key={item} value={item}>{item}</option>)}</select></label> : null}
      <label><span>Elapsed UTC cadence</span><select value={intervalDays} onChange={(event) => { setIntervalDays(Number(event.target.value) as 7 | 14 | 30); setConfirmed(false); }}><option value={7}>Every 7 days</option><option value={14}>Every 14 days</option><option value={30}>Every 30 days</option></select></label>
      <label><span>IANA timezone</span><input value={timezoneName} maxLength={64} onChange={(event) => { setTimezoneName(event.target.value); setConfirmed(false); }} placeholder="Europe/Madrid" /></label>
      <label><span>Authorized weekday</span><select value={windowWeekday} onChange={(event) => { setWindowWeekday(event.target.value as (typeof WEEKDAYS)[number]); setConfirmed(false); }}>{WEEKDAYS.map((day) => <option key={day} value={day}>{day[0].toUpperCase() + day.slice(1)}</option>)}</select></label>
      <label><span>Window starts</span><select value={windowStartHour} onChange={(event) => { const hour = Number(event.target.value); setWindowStartHour(hour); if (hour + windowDurationHours > 24) setWindowDurationHours(1); setConfirmed(false); }}>{Array.from({ length: 24 }, (_, hour) => <option key={hour} value={hour}>{String(hour).padStart(2, '0')}:00</option>)}</select></label>
      <label><span>Window duration</span><select value={windowDurationHours} onChange={(event) => { setWindowDurationHours(Number(event.target.value) as 1 | 2 | 4 | 8); setConfirmed(false); }}>{([1, 2, 4, 8] as const).filter((hours) => windowStartHour + hours <= 24).map((hours) => <option key={hours} value={hours}>{hours} hour{hours === 1 ? '' : 's'}</option>)}</select></label>
      <label className="checkbox-row"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />I authorize future bounded runs at this cadence while the exact authorization and verification remain valid.</label>
      {selectedAlreadyScheduled ? <p className="warning-text" role="status">This exact capability and port already has a schedule. Pause, resume or remove the existing policy instead.</p> : null}
      <button type="button" disabled={!confirmed || !timezoneName.trim() || busyId !== null || selectedAlreadyScheduled || (capability === 'active_tls_basic' && typeof port !== 'number')} onClick={() => void create()}>{busyId === 'create' ? 'Scheduling…' : 'Schedule recurring review'}</button>
    </div> : !loading && enabled && canManage ? <p className="warning-text" role="status">A current verified control signal and active immutable authorization are required before scheduling or resuming.</p> : null}
    <p className="muted">Missed intervals collapse into one eligible run; Inspectra never launches a catch-up storm. Availability failures use a persisted, bounded backoff and remain inside the authorized weekly window.</p>
    {notice ? <p className="success-text" role="status">{notice}</p> : null}
    {error ? <p className="error-text" role="alert">{error}</p> : null}
  </section>;
}
