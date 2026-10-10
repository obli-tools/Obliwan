import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { cn } from '@/utils/cn';
import {
  SITE_DEPLOYMENT_STATES,
  type SiteDeployment,
  type SiteDeploymentMeta,
  type SiteDeploymentState,
} from '@/api/sites.api';

/** The server's thresholds, from the deployment endpoint's `meta`. */
export type SiteDeploymentLimits = Pick<SiteDeploymentMeta, 'pppDownGraceMinutes'>;

/**
 * The deployment state of a site, as the account manager reads it on the sites
 * list: a coloured badge, "depuis …", and the reason in the tooltip.
 *
 * The state is computed by the server (services/fleet/siteDeployment.service.ts)
 * and only DRAWN here: a second classification in the browser would be free to
 * disagree with the one the Excel export uses.
 *
 * Plain French defaults on purpose: this screen is read by an account manager,
 * not an engineer. The keys under `sites.deployment.*` are the place to
 * translate it.
 */

const STATE_DEFAULT_LABEL: Record<SiteDeploymentState, string> = {
  anomaly: 'En anomalie',
  online: 'En ligne',
  prepared: 'Préparé au banc',
  ready: 'À préparer',
  allocated_pending_chr: 'En attente du concentrateur',
  to_allocate: 'Adresses à attribuer',
  not_applicable: 'Non concerné',
};

/** Pill classes per state. Anomaly is the only red; "not applicable" and
 *  "to allocate" are hollow so they never read as a status of the network. */
const STATE_PILL: Record<SiteDeploymentState, string> = {
  anomaly: 'bg-status-down/10 border-status-down/40 text-status-down',
  online: 'bg-status-up/10 border-status-up/30 text-status-up',
  prepared: 'bg-accent/10 border-accent/30 text-accent',
  ready: 'bg-status-maintenance/10 border-status-maintenance/30 text-status-maintenance',
  allocated_pending_chr: 'bg-status-pending/10 border-status-pending/40 text-status-pending',
  to_allocate: 'bg-transparent border-dashed border-text-muted/50 text-text-secondary',
  not_applicable: 'bg-transparent border-dashed border-text-muted/40 text-text-muted',
};

const STATE_DOT: Record<SiteDeploymentState, string> = {
  anomaly: 'bg-status-down',
  online: 'bg-status-up',
  prepared: 'bg-accent',
  ready: 'bg-status-maintenance',
  allocated_pending_chr: 'bg-status-pending',
  to_allocate: 'border border-text-muted bg-transparent',
  not_applicable: 'border border-text-muted/60 bg-transparent',
};

export function deploymentStateLabel(t: TFunction, state: SiteDeploymentState): string {
  return t(`sites.deployment.state.${state}`, { defaultValue: STATE_DEFAULT_LABEL[state] });
}

/** "3 min", "5 h", "12 j" — the age of the state, in the unit a person uses. */
function shortDuration(t: TFunction, sinceIso: string, nowMs: number): string | null {
  const ms = nowMs - new Date(sinceIso).getTime();
  if (!Number.isFinite(ms)) return null;
  const minutes = Math.max(0, Math.floor(ms / 60_000));
  if (minutes < 60) {
    return t('sites.deployment.duration.minutes', { defaultValue: '{{count}} min', count: minutes });
  }
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return t('sites.deployment.duration.hours', { defaultValue: '{{count}} h', count: hours });
  return t('sites.deployment.duration.days', { defaultValue: '{{count}} j', count: Math.floor(hours / 24) });
}

function formatInstant(iso: string | null, lang: string): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return new Intl.DateTimeFormat(lang, { dateStyle: 'short', timeStyle: 'short' }).format(d);
}

/** Reasons whose sentence names the device, or the bench workstation. */
const NAMES_DEVICE = new Set(['device_quarantined', 'router_down', 'health_ok']);
const NAMES_STATION = new Set(['bench_failed', 'bench_applied', 'bench_applied_chr_pending', 'bench_compiled']);
/** Reasons whose sentence quotes one of the server's thresholds. */
const NAMES_LIMIT = new Set(['tunnel_down', 'reconnecting']);

/** The reason as a sentence: the localised key when one exists, else the
 *  server's French sentence (the same text as the export's "Détail"). When a
 *  value the sentence interpolates is missing, the server's sentence — which
 *  leaves a missing name out cleanly and already holds the thresholds — is
 *  used rather than a key with an empty « » or a blank number. */
function reasonSentence(t: TFunction, row: SiteDeployment, limits: SiteDeploymentLimits | null): string {
  if (
    (NAMES_DEVICE.has(row.reason) && !row.detailParams.device) ||
    (NAMES_STATION.has(row.reason) && !row.detailParams.station) ||
    (NAMES_LIMIT.has(row.reason) && !limits)
  ) {
    return row.detail;
  }
  return t(`sites.deployment.reason.${row.reason}`, {
    defaultValue: row.detail,
    device: row.detailParams.device ?? '',
    station: row.detailParams.station ?? '',
    minutes: limits?.pppDownGraceMinutes ?? '',
  });
}

/** The tooltip: the reason, then the facts behind it, one per line. */
function tooltip(t: TFunction, row: SiteDeployment, lang: string, limits: SiteDeploymentLimits | null): string {
  const lines = [reasonSentence(t, row, limits)];
  const since = formatInstant(row.since, lang);
  if (since) lines.push(t('sites.deployment.tip.since', { defaultValue: 'Depuis le {{date}}', date: since }));
  const prepared = formatInstant(row.preparedAt, lang);
  if (prepared) {
    lines.push(
      row.preparedBy
        ? t('sites.deployment.tip.preparedBy', {
          defaultValue: 'Préparé le {{date}} sur le poste {{station}}',
          date: prepared,
          station: row.preparedBy,
        })
        : t('sites.deployment.tip.prepared', { defaultValue: 'Préparé le {{date}}', date: prepared }),
    );
  }
  const online = formatInstant(row.onlineSince, lang);
  if (online) lines.push(t('sites.deployment.tip.onlineSince', { defaultValue: 'Tunnel établi depuis le {{date}}', date: online }));
  if (row.pppLogin) lines.push(t('sites.deployment.tip.login', { defaultValue: 'Login PPP : {{login}}', login: row.pppLogin }));
  if (row.tunnelIp) lines.push(t('sites.deployment.tip.tunnelIp', { defaultValue: 'IP tunnel : {{ip}}', ip: row.tunnelIp }));
  if (row.device) {
    const model = row.device.model ? ` (${row.device.model})` : '';
    lines.push(t('sites.deployment.tip.device', {
      defaultValue: 'Routeur : {{name}}{{model}}',
      name: row.device.name,
      model,
    }));
  }
  return lines.join('\n');
}

export function SiteDeploymentBadge({
  row,
  nowMs,
  limits,
}: {
  row: SiteDeployment | undefined;
  /** The instant the states were computed — the server's clock, so that
   *  "depuis …" and the state agree whatever the browser's clock says. */
  nowMs: number;
  limits: SiteDeploymentLimits | null;
}) {
  const { t, i18n } = useTranslation();
  const lang = i18n.language;
  if (!row) return <span className="text-xs text-text-muted">—</span>;
  const age = row.since ? shortDuration(t, row.since, nowMs) : null;
  const title = tooltip(t, row, lang, limits);
  return (
    <div className="flex flex-col items-start gap-0.5" title={title}>
      <span
        className={cn(
          'inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-[11px] font-medium',
          STATE_PILL[row.state],
        )}
      >
        <span className={cn('inline-block h-1.5 w-1.5 shrink-0 rounded-full', STATE_DOT[row.state])} />
        {deploymentStateLabel(t, row.state)}
      </span>
      {age && (
        <span className="text-[10px] text-text-muted">
          {row.reason === 'health_ok'
            // There is no "up since" for a health answer: `since` is the latest
            // successful check, and "depuis" would claim more than that.
            ? t('sites.deployment.checkedAgo', { defaultValue: 'vérifié il y a {{duration}}', duration: age })
            : t('sites.deployment.sinceShort', { defaultValue: 'depuis {{duration}}', duration: age })}
        </span>
      )}
      <span className="sr-only">{title}</span>
    </div>
  );
}

/**
 * One chip per state present in the list (plus the selected one), each with
 * its count — "12 Préparé au banc · 3 En anomalie". Clicking a chip filters
 * the table; clicking it again, or "Tous", clears the filter.
 */
export function SiteDeploymentChips({
  counts,
  total,
  selected,
  onSelect,
}: {
  counts: Record<SiteDeploymentState, number>;
  total: number;
  selected: SiteDeploymentState | null;
  onSelect: (state: SiteDeploymentState | null) => void;
}) {
  const { t } = useTranslation();
  const visible = SITE_DEPLOYMENT_STATES.filter((s) => counts[s] > 0 || s === selected);
  return (
    <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label={t('sites.deployment.filterLabel', { defaultValue: 'Filtrer par état' })}>
      <button
        type="button"
        onClick={() => onSelect(null)}
        aria-pressed={selected === null}
        className={cn(
          'rounded-full border px-2.5 py-0.5 text-[11px] font-medium transition-colors',
          selected === null
            ? 'border-text-secondary bg-bg-hover text-text-primary'
            : 'border-border text-text-secondary hover:bg-bg-hover',
        )}
      >
        {t('sites.deployment.all', { defaultValue: 'Tous ({{count}})', count: total })}
      </button>
      {visible.map((s) => (
        <button
          key={s}
          type="button"
          onClick={() => onSelect(selected === s ? null : s)}
          aria-pressed={selected === s}
          className={cn(
            'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-medium transition-colors',
            STATE_PILL[s],
            selected === s ? 'ring-1 ring-current' : 'opacity-80 hover:opacity-100',
          )}
        >
          <span className={cn('inline-block h-1.5 w-1.5 shrink-0 rounded-full', STATE_DOT[s])} />
          <span className="font-mono">{counts[s]}</span>
          {deploymentStateLabel(t, s)}
        </button>
      ))}
    </div>
  );
}
