import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Info, KeyRound } from 'lucide-react';
import {
  MB_PER_GB,
  SIM_LINE_SECRET_FIELDS,
  type SimLineSecretField,
  type SimLineStatus,
} from '@obliwan/shared';
import type { SimLineListItem } from '@/api/sim.api';
import { secretsApi } from '@/api/secrets.api';
import { RevealSecretButton } from '@/components/secrets/RevealSecretButton';
import { EmptyState, Panel, When } from '@/components/mobile/SimBits';
import { cn } from '@/utils/cn';

/**
 * ObliWAN — everything the partner's listing says about one line
 * (migration 077; observed on the production extranet, 2026-10-06).
 *
 * ┌─ THREE RULES THIS PANEL KEEPS ────────────────────────────────────────────┐
 * │ 1. CONSUMPTION IS NOT A BALANCE. The four figures are data USED, as the   │
 * │    partner prints it. Nothing here subtracts them from anything: the      │
 * │    listing carries no allowance, and a computed "remaining" is the number │
 * │    that buys data. The hint under the block says so.                      │
 * │ 2. EMPTY IS "—", NEVER 0. `null` reaches this component when the partner  │
 * │    left a field empty, and it is drawn as a dash; a real 0 is drawn as 0. │
 * │ 3. THE SECRETS ARE NOT HERE. PUK1, PUK2, the RADIUS password and the RIO  │
 * │    (the porting code — operator decision 2026-10-06, migration 079): the │
 * │    line carries only whether each one is stored; a value exists in this  │
 * │    page only inside `RevealSecretButton`, for 30 seconds, after an        │
 * │    audited `POST /sim/lines/:id/reveal` that needs SECRET_READ on top of  │
 * │    SIM_READ. None of them is ever in "other fields" (`details`): the      │
 * │    server keeps them out, and migration 079 refuses a RIO key there.      │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

const STATUS_CLASS: Record<SimLineStatus, string> = {
  active: 'bg-status-up/15 text-status-up border-status-up/30',
  suspended: 'bg-status-ssl-warning/15 text-status-ssl-warning border-status-ssl-warning/30',
  terminated: 'bg-status-down/15 text-status-down border-status-down/30',
  unknown: 'bg-text-muted/10 text-text-secondary border-border',
};

export function LineStatusBadge({ status }: { status: SimLineStatus }) {
  const { t } = useTranslation();
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium',
        STATUS_CLASS[status] ?? STATUS_CLASS.unknown,
      )}
    >
      {t(`mobile.partner.status.${status}`)}
    </span>
  );
}

/** A consumption figure in MB, with the decimals the partner gave, plus GB
 *  past one gigabyte. `null` is a dash — never "0 Mo". */
function useMbFormat(): (mb: number | null) => string {
  const { i18n } = useTranslation();
  const n2 = new Intl.NumberFormat(i18n.language, { maximumFractionDigits: 2 });
  return (mb) => {
    if (mb === null) return '—';
    const base = `${n2.format(mb)} Mo`;
    return mb >= MB_PER_GB ? `${base} (${n2.format(mb / MB_PER_GB)} Go)` : base;
  };
}

function Dash() {
  return <span className="text-text-muted">—</span>;
}

function Field({ label, children, mono = false }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] text-text-muted">{label}</dt>
      <dd className={cn('mt-0.5 break-words text-[13px] text-text-primary', mono && 'font-mono')}>{children}</dd>
    </div>
  );
}

function Section({ title, children, hint }: { title: string; children: ReactNode; hint?: string }) {
  return (
    <div className="px-4 py-3">
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-text-secondary">{title}</h3>
      <dl className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-2 lg:grid-cols-4">{children}</dl>
      {hint ? (
        <p className="mt-2 flex items-start gap-2 text-[11px] text-text-muted">
          <Info size={12} className="mt-0.5 shrink-0" />
          {hint}
        </p>
      ) : null}
    </div>
  );
}

/** A verbatim partner value: strings as typed, "" shown as such, the rest as JSON. */
function Verbatim({ value }: { value: unknown }) {
  const { t } = useTranslation();
  if (value === null || value === undefined) return <Dash />;
  if (value === '') return <span className="text-text-muted">{t('mobile.partner.empty')}</span>;
  if (typeof value === 'string') return <>{value}</>;
  return <span className="font-mono">{JSON.stringify(value)}</span>;
}

export function SimPartnerFactsPanel({ line }: { line: SimLineListItem }) {
  const { t } = useTranslation();
  const mb = useMbFormat();
  const p = line.partner;
  const text = (v: string | null) => (v === null ? <Dash /> : v);
  const yesNo = (v: boolean | null) => (v === null ? <Dash /> : v ? t('mobile.partner.yes') : t('mobile.partner.no'));

  if (!p) {
    return (
      <Panel className="mt-6" title={t('mobile.partner.title')}>
        <EmptyState message={t('mobile.partner.none')} />
      </Panel>
    );
  }

  const raw = [p.state, p.stateLabel].filter((v): v is string => v !== null).join(' / ');
  const other = Object.entries(p.details ?? {}).sort(([a], [b]) => a.localeCompare(b));
  const secretLabel: Record<SimLineSecretField, string> = {
    puk1: t('mobile.partner.fields.puk1'),
    puk2: t('mobile.partner.fields.puk2'),
    radiusPassword: t('mobile.partner.fields.radiusPassword'),
    rio: t('mobile.partner.fields.rio'),
  };

  return (
    <Panel className="mt-6" title={t('mobile.partner.title')}>
      <div className="divide-y divide-border">
        <Section title={t('mobile.partner.sections.identity')}>
          <Field label={t('mobile.partner.fields.status')}>
            <span className="inline-flex flex-wrap items-center gap-2">
              <LineStatusBadge status={line.status} />
              {raw !== '' ? (
                <span className="text-[11px] text-text-muted">{t('mobile.partner.rawState', { value: raw })}</span>
              ) : null}
            </span>
          </Field>
          <Field label={t('mobile.partner.fields.partnerLineId')} mono>{text(p.partnerLineId)}</Field>
          <Field label={t('mobile.partner.fields.operator')}>{text(line.operator)}</Field>
          <Field label={t('mobile.partner.fields.simType')}>{text(p.simType)}</Field>
          <Field label={t('mobile.partner.fields.simSerial')} mono>{text(p.simSerial)}</Field>
          <Field label={t('mobile.partner.fields.iccid')} mono>{text(line.iccid)}</Field>
          <Field label={t('mobile.partner.fields.imsi')} mono>{text(p.imsi)}</Field>
          <Field label={t('mobile.partner.fields.activatedAt')}><When iso={p.activatedAt} /></Field>
          <Field label={t('mobile.partner.fields.terminatedAt')}><When iso={p.terminatedAt} /></Field>
        </Section>

        <Section title={t('mobile.partner.sections.customer')}>
          <Field label={t('mobile.partner.fields.clientCode')} mono>{text(line.clientCode)}</Field>
          <Field label={t('mobile.partner.fields.customerName')}>{text(p.customerName)}</Field>
          <Field label={t('mobile.partner.fields.siteLabel')}>{text(p.siteLabel)}</Field>
          <Field label={t('mobile.partner.fields.internalRef')}>{text(p.internalRef)}</Field>
        </Section>

        <Section title={t('mobile.partner.sections.offer')}>
          <Field label={t('mobile.partner.fields.planLabel')}>{text(p.planLabel)}</Field>
          <Field label={t('mobile.partner.fields.planCode')} mono>{text(p.planCode)}</Field>
          <Field label={t('mobile.partner.fields.offerType')} mono>{text(p.offerType)}</Field>
          <Field label={t('mobile.partner.fields.purchaseTariffCode')} mono>{text(p.purchaseTariffCode)}</Field>
          <Field label={t('mobile.partner.fields.dataOnly')}>{yesNo(p.dataOnly)}</Field>
          <Field label={t('mobile.partner.fields.apn')} mono>{text(p.apn)}</Field>
          <Field label={t('mobile.partner.fields.fixedIp')} mono>
            {p.fixedIp ?? (p.hasFixedIp === false ? t('mobile.partner.noFixedIp') : <Dash />)}
          </Field>
          <Field label={t('mobile.partner.fields.radiusLogin')} mono>{text(p.radiusLogin)}</Field>
        </Section>

        <Section title={t('mobile.partner.sections.consumption')} hint={t('mobile.partner.consumptionHint')}>
          <Field label={t('mobile.partner.fields.nationalMb')}>{mb(p.consumption.nationalMb)}</Field>
          <Field label={t('mobile.partner.fields.roamingMb')}>{mb(p.consumption.roamingMb)}</Field>
          <Field label={t('mobile.partner.fields.nationalPrevMonthMb')}>{mb(p.consumption.nationalPrevMonthMb)}</Field>
          <Field label={t('mobile.partner.fields.roamingPrevMonthMb')}>{mb(p.consumption.roamingPrevMonthMb)}</Field>
        </Section>

        <Section title={t('mobile.partner.sections.secrets')} hint={t('mobile.partner.secretsHint')}>
          {SIM_LINE_SECRET_FIELDS.map((field) => (
            <Field key={field} label={secretLabel[field]}>
              {p.secretsStored[field] ? (
                <span className="inline-flex flex-wrap items-center gap-2">
                  <span className="inline-flex items-center gap-1 text-text-secondary">
                    <KeyRound size={12} />
                    {t('mobile.partner.secretStored')}
                  </span>
                  <RevealSecretButton
                    label={secretLabel[field]}
                    // A new line, or the same line re-read after a sweep that
                    // may have replaced the value: drop what was shown.
                    resetKey={`${line.id}:${field}:${p.observedAt}`}
                    reveal={() => secretsApi.revealSimLineSecret(line.id, field)}
                  />
                </span>
              ) : (
                <span className="text-text-muted">{t('mobile.partner.secretAbsent')}</span>
              )}
            </Field>
          ))}
        </Section>

        {other.length > 0 ? (
          <Section title={t('mobile.partner.sections.other')} hint={t('mobile.partner.otherHint')}>
            {other.map(([key, value]) => (
              <Field key={key} label={key}>
                <Verbatim value={value} />
              </Field>
            ))}
          </Section>
        ) : null}
      </div>
      <p className="border-t border-border px-4 py-2 text-[11px] text-text-muted">
        {t('mobile.partner.observedAt', { when: new Date(p.observedAt).toLocaleString() })}
      </p>
    </Panel>
  );
}
