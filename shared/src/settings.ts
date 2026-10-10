// ============================================================================
// @obliwan/shared — hierarchical settings contract
// ============================================================================
//
// A setting is a NUMERIC value resolved along the inheritance chain
// global → tenant → group chain → device (see `settings.service.ts`).
// `scope` is 'global' | 'group' | 'device'; `HARDCODED_DEFAULTS`
// is the floor used when nothing is stored at any level.
//
// Non-numeric preferences (theme, language, toast position) live on the USER,
// not here — see `UserPreferences` in types.ts. Do not add string settings to
// this table without changing `SettingValue.value` and every consumer.
//
// Values that are NOT settings and must never move here: credentials (vault),
// the SSO configuration and the global kill-switch (`app_config`).

export const SETTINGS_KEYS = {
  // ── Notifications ──────────────────────────────────────────────────────
  /** Minimum seconds between two identical notifications for the same key. */
  NOTIFICATION_COOLDOWN: 'notification_cooldown',
  /**
   * What the CHANNELS hear of a down or 4G backup alert raised while the
   * store is CLOSED (opening hours, migration 096): 0 = notify anyway, at the
   * lowered severity (what happened before the hours existed); 1 = wait for
   * the opening, and notify then only if the problem is still there. The live
   * alert is raised either way. Read per device.
   */
  CLOSED_STORE_NOTIFY: 'closed_store_notify',

  // ── Reachability / presence ────────────────────────────────────────────
  /**
   * Seconds a PPP session may stay down before the device is declared DOWN.
   * Read per device (`pppPresence.service.ts`, `reachability.service.ts`).
   * 0 — the default — is what presence did before the setting was read: the
   * verdict follows the session within the two seconds presence promises.
   */
  PRESENCE_GRACE_PERIOD: 'presence_grace_period',
  /** Milliseconds before a transport connection attempt is abandoned. */
  DEVICE_TIMEOUT: 'device_timeout',
  /** Seconds between two permanent checks of a device's management channel. */
  HEALTH_CHECK_INTERVAL: 'health_check_interval',
  /** Consecutive failed checks tolerated before a device is declared down. */
  HEALTH_CHECK_RETRIES: 'health_check_retries',
  /**
   * Seconds a CONFIRMED-down device stays down before its alert is raised.
   * Counted from the confirmation (the failure that exhausted the retries),
   * not from the first failure.
   */
  HEALTH_ALERT_DELAY: 'health_alert_delay',
  /**
   * Minutes a router's ACTIVE default route may stay on its cellular link,
   * while the site has a fixed uplink, before ONE backup alert is raised
   * (fleet/backup4g.service.ts). 0 = off.
   */
  BACKUP_4G_ALERT_DELAY: 'backup_4g_alert_delay',
  /**
   * The grouped operator outage (migration 095,
   * fleet/operatorOutage.service.ts): at least this many stores of the same
   * provider losing their fixed line within OPERATOR_OUTAGE_WINDOW minutes
   * open ONE alert instead of one per store. PLATFORM-WIDE (`workspaceOnly`,
   * read on the main workspace): an operator outage hits several customers,
   * so the grouping spans every workspace.
   */
  OPERATOR_OUTAGE_MIN_STORES: 'operator_outage_min_stores',
  /** Minutes within which those stores must have lost their fixed line. */
  OPERATOR_OUTAGE_WINDOW: 'operator_outage_window',

  // ── Line quality of the fixed line (migration 097) ─────────────────────
  //
  // Read per device by `fleet/lineQuality.service.ts`: the nightly pings
  // through the fixed line, and the thresholds a night is judged with.
  /** First ping target, an IPv4 address stored as its 32-bit value; 0 = none. */
  LINE_QUALITY_TARGET_1: 'line_quality_target_1',
  /** Second ping target, same encoding; 0 = none. Both 0 = no ping at all. */
  LINE_QUALITY_TARGET_2: 'line_quality_target_2',
  /** Local hour (site time zone) the night window opens, when the store's
   *  opening hours are unknown. */
  LINE_QUALITY_NIGHT_START: 'line_quality_night_start',
  /** Local hour the night window closes. */
  LINE_QUALITY_NIGHT_END: 'line_quality_night_end',
  /** Packet loss (%) at or above which a night exceeds; 0 = rule off. */
  LINE_QUALITY_LOSS_PCT: 'line_quality_loss_pct',
  /** Average round trip (ms) at or above which a night exceeds; 0 = off. */
  LINE_QUALITY_LATENCY_MS: 'line_quality_latency_ms',
  /** Reconnections of the day at or above which a night exceeds; 0 = off. */
  LINE_QUALITY_RECONNECTIONS: 'line_quality_reconnections',
  /** Above the site's own 14-night baseline by this percentage; 0 = off. */
  LINE_QUALITY_RELATIVE_PCT: 'line_quality_relative_pct',
  /** Consecutive exceeded nights that make a line « dégradée ». */
  LINE_QUALITY_NIGHTS: 'line_quality_nights',

  // ── SNMP polling ───────────────────────────────────────────────────────
  //
  // All three are read per device by `snmp/targets.ts` for a target whose own
  // column is NULL ("inherit"); a value pinned on the target wins. Their
  // defaults are the numbers the poller ran on before they were read — 30 s,
  // 2 s, one retry, the figures the SNMP storage and concurrency study is
  // dimensioned on — not the 60 s / 5 s / 2 this table used to advertise.
  /** Seconds between two polls of a device's interface counters. */
  SNMP_POLL_INTERVAL: 'snmp_poll_interval',
  /** Milliseconds before one SNMP request is considered lost. */
  SNMP_TIMEOUT: 'snmp_timeout',
  /** Retries of one SNMP request before the poll is marked failed. */
  SNMP_RETRIES: 'snmp_retries',
  /**
   * The `snmp_credentials` row new devices are polled with — 0 means "do not
   * create targets automatically".
   *
   * ONE setting rather than an on/off plus a credential, because the pair has
   * an invalid combination — enabled with no credential — that would present as
   * "supervision is on and nothing is ever polled". Here that state cannot be
   * written down: 0 IS off, and any other value names the credential.
   */
  SNMP_AUTO_TARGET_CREDENTIAL: 'snmp_auto_target_credential',

  // ── Bench preparation ───────────────────────────────────────────────────
  /**
   * The `device_groups` row a device CREATED at the bench is placed in — 0
   * means "no group", which is what the bench did before this setting existed.
   *
   * WORKSPACE-WIDE (`workspaceOnly`): it is read when the device does not
   * exist yet, so there is no group or device chain to inherit through, and a
   * group override would be a value nothing reads. A value naming no group of
   * this workspace (deleted since, or another workspace's id) is NOT applied:
   * the device is created with no group and the compile says so
   * (`services/bench/compile.service.ts`, `benchDefaultGroup`).
   */
  BENCH_DEFAULT_GROUP: 'bench_default_group',

  // ── Configuration collection & drift ───────────────────────────────────
  /** Minutes between two config snapshots of the same device. */
  SNAPSHOT_INTERVAL: 'snapshot_interval',
  /** Minutes between two drift runs. */
  DRIFT_INTERVAL: 'drift_interval',

  // ── Safe-Apply ─────────────────────────────────────────────────────────
  /**
   * Seconds the on-device dead-man waits before self-rollback. Read per device
   * when a job is claimed (`change/applyTimings.ts`), together with the soak:
   * a window that cannot hold reconnect + soak + disarm refuses the job before
   * its backup is taken, rather than reverting a good change by our own clock.
   */
  COMMIT_CONFIRM_TIMEOUT: 'commit_confirm_timeout',
  /** Seconds of post-apply soak before the dead-man is disarmed. Per device. */
  APPLY_SOAK_SECONDS: 'apply_soak_seconds',
  /**
   * Maximum change jobs one worker process runs at the same time. PLATFORM-WIDE:
   * the queue is one per installation, so only the main workspace's value is
   * read (`change/jobQueue.service.ts`).
   */
  MAX_CONCURRENT_JOBS: 'max_concurrent_jobs',
  /**
   * 1 = a site with NO explicit maintenance window takes its store's CLOSED
   * hours as its window (change/jobQueue.service.ts, openingHours.service.ts).
   * 0 — the default — is the queue's rule before 096: no window, no
   * constraint. An explicit window is never overridden. Read per device.
   */
  CLOSED_HOURS_MAINTENANCE: 'closed_hours_maintenance',

  // ── Nightly verification of the management access (migration 093) ──────
  //
  // Read per WORKSPACE (`workspaceOnly`) by fleet/accessCheckNightly.service.ts:
  // the verification covers a whole workspace, so a group or device override
  // would be a value nothing reads.
  /** 1 (the default) = every active router of the workspace is verified once
   *  a night — read-only towards the routers. 0 = off. */
  ACCESS_CHECK_NIGHTLY: 'access_check_nightly',
  /** The hour (0-23, Europe/Paris) the nightly verification starts at. */
  ACCESS_CHECK_NIGHTLY_HOUR: 'access_check_nightly_hour',
  /**
   * 1 = right after the nightly verification, queue the management access /
   * template-fix jobs it found needed. 0 — the default — writes nothing.
   * Turning it on is the platform administrator's standing safety-net confirmation
   * of the degraded level: the setting write records who and when
   * (`access_check_auto_consents`), and the jobs carry that confirmation.
   */
  ACCESS_CHECK_AUTO_REAPPLY: 'access_check_auto_reapply',
  /** Routers the automatic re-apply queues a job on per night, at most. */
  ACCESS_CHECK_AUTO_REAPPLY_CAP: 'access_check_auto_reapply_cap',

  // ── Mobile data lines / SIM fleet ──────────────────────────────────────
  /** Minutes between two sweeps of a partner account's lines and balances. */
  SIM_SYNC_INTERVAL: 'sim_sync_interval',
  /**
   * Default low-data threshold, in MEGABYTES, for a line with no override.
   *
   * MB rather than GB because settings are integers and a 0.5 GB threshold has
   * to be representable — and because `sim_lines.low_threshold_mb` is in the
   * same unit, so the comparison that decides whether a top-up is proposed
   * never crosses a conversion. 1024 = 1 Go, the value the field prototype ran.
   */
  SIM_LOW_DATA_THRESHOLD: 'sim_low_data_threshold',
  /**
   * Percentage of a zone's data ENVELOPE used at or above which the zone is
   * reported low (brick 6). Applied per zone, only when that zone's envelope is
   * known (`zoneEnvelope`, shared/src/sim.ts); a zone with no known envelope
   * keeps `SIM_LOW_DATA_THRESHOLD` (MB remaining) as its labelled fallback.
   */
  SIM_LOW_DATA_PERCENT: 'sim_low_data_percent',
  /**
   * Hours before the same still-low line is announced again.
   *
   * Distinct from the top-up idempotency key, which allows exactly ONE proposal
   * per low episode and never repeats. This is about the reminder: a proposal
   * nobody has acted on for three days should say so again, and every four
   * hours is how an operator learns to filter the channel out.
   */
  SIM_ALERT_REMIND_HOURS: 'sim_alert_remind_hours',

  // ── Retention ──────────────────────────────────────────────────────────
  //
  // Enforced by `services/retention/dataRetention.service.ts` (leader, daily)
  // and, for the time series, by the hourly partition maintenance.
  /**
   * Days the 5-minute interface and device rollups are kept. PLATFORM-WIDE: a
   * partition holds every tenant's rows, so only the main workspace's value is
   * read. Raw samples (48 h), 1-minute rollups (8 days) and hourly rollups
   * (2 years) keep the retention the storage study fixed. The previous wording,
   * "raw samples", described a 90-day raw tier that has never existed: 90 days
   * of raw samples is some 600 M rows.
   */
  TIMESERIES_RETENTION_DAYS: 'timeseries_retention_days',
  /**
   * Days a SUPERSEDED config snapshot is kept after it was last observed. Per
   * device. The current snapshot of a device is never removed, and neither is
   * one a change plan, an intervention or a drift run with findings refers to.
   */
  CONFIG_RETENTION_DAYS: 'config_retention_days',
  /**
   * Days of audit-ledger and command-audit rows kept. Per workspace (the
   * ledger is a per-tenant hash chain, truncated from its oldest end). Never
   * below 400: the database refuses to delete a younger row of either table
   * (migrations 009 and 019).
   */
  AUDIT_RETENTION_DAYS: 'audit_retention_days',
  /**
   * Days the append-only EVENT histories are kept (reachability verdicts, WAN
   * path events, identity events/observations, intervention lifecycle events,
   * SIM balance samples and sweep journal, CWMP sessions). PLATFORM-WIDE: one
   * purge for the whole installation, so only the main workspace's value is
   * read. Rows still in use are never removed, whatever their age: the latest
   * row a state is derived from, and rows another record names as evidence
   * (see `dataRetention.service.ts`).
   */
  EVENT_HISTORY_RETENTION_DAYS: 'event_history_retention_days',
  /**
   * Days the RUN / JOB histories are kept (drift runs without findings, change
   * job step traces, baseline mining runs, configuration renders, stale
   * pending discoveries). PLATFORM-WIDE, like the one above. A running job, the
   * latest run of a device and anything still named as evidence are kept.
   */
  RUN_HISTORY_RETENTION_DAYS: 'run_history_retention_days',
} as const;

export type SettingsKey = (typeof SETTINGS_KEYS)[keyof typeof SETTINGS_KEYS];

export const SETTING_CATEGORIES = [
  'notifications',
  'reachability',
  'snmp',
  'configuration',
  'change',
  'mobile',
  'retention',
] as const;

export type SettingCategory = (typeof SETTING_CATEGORIES)[number];

export interface SettingDefinition {
  key: SettingsKey;
  category: SettingCategory;
  label: string;
  description: string;
  type: 'number';
  unit: string;
  default: number;
  min: number;
  max: number;
  /**
   * Read at the workspace (`global`) level only. A group or device override of
   * such a key would be stored and never read, so `settings.service` refuses
   * the write and `SettingsPanel` does not offer it below the global scope.
   */
  workspaceOnly?: true;
  /**
   * A closed list of values with their meaning: the field is a select, not a
   * number input. The stored value is still the number.
   */
  choices?: Array<{ value: number; label: string }>;
}

export const SETTINGS_DEFINITIONS: SettingDefinition[] = [
  {
    key: SETTINGS_KEYS.NOTIFICATION_COOLDOWN,
    category: 'notifications',
    label: 'Notification cooldown',
    description: 'Minimum time between repeated notifications for the same event',
    type: 'number',
    unit: 'seconds',
    default: 300,
    min: 0,
    max: 86400,
  },
  {
    key: SETTINGS_KEYS.CLOSED_STORE_NOTIFY,
    category: 'notifications',
    label: 'Notifications for a closed store',
    description:
      'A down or 4G backup alert raised while the store is closed (per its opening hours) is shown one '
      + 'level lower and marked "store closed"; it is raised again at its normal severity when the store '
      + 'opens with the problem still there, and notified then. This decides whether the notification '
      + 'channels also hear of it at once (at the lowered severity) or only at the opening. A store with '
      + 'no known hours is not concerned.',
    type: 'number',
    unit: '',
    default: 0,
    min: 0,
    max: 1,
    choices: [
      { value: 0, label: 'Notify anyway' },
      { value: 1, label: 'Wait for the opening' },
    ],
  },
  {
    key: SETTINGS_KEYS.PRESENCE_GRACE_PERIOD,
    category: 'reachability',
    label: 'Presence grace period',
    description:
      'How long a PPP session may stay down before the device is reported DOWN. A session that '
      + 'comes back within this window is recorded in the session history but never shown as an '
      + 'outage. 0 reports the drop at once.',
    type: 'number',
    unit: 'seconds',
    // 0, not the 120 this table used to advertise and nothing read: 0 is what
    // presence has always done ("flips in under 2 s"), and a default that
    // silently delayed every outage by two minutes would be a new behaviour
    // nobody chose.
    default: 0,
    min: 0,
    max: 3600,
  },
  {
    key: SETTINGS_KEYS.DEVICE_TIMEOUT,
    category: 'reachability',
    label: 'Device timeout',
    description: 'Time before a transport connection attempt is abandoned',
    type: 'number',
    unit: 'ms',
    default: 15000,
    min: 1000,
    max: 120000,
  },
  {
    key: SETTINGS_KEYS.HEALTH_CHECK_INTERVAL,
    category: 'reachability',
    label: 'Health check interval',
    description:
      "How often each device's management channel is checked: a RouterOS API read when the "
      + 'device has an API channel, otherwise a TCP connection to its SSH or HTTPS port. A device '
      + 'behind a concentrator whose PPP session is down is not dialled; the check counts as failed.',
    type: 'number',
    unit: 'seconds',
    default: 60,
    min: 10,
    max: 86400,
  },
  {
    key: SETTINGS_KEYS.HEALTH_CHECK_RETRIES,
    category: 'reachability',
    label: 'Health check retries',
    description:
      'Consecutive failed checks tolerated before the device is declared down. '
      + '0 means the first failure counts.',
    type: 'number',
    unit: 'retries',
    default: 3,
    min: 0,
    max: 10,
  },
  {
    key: SETTINGS_KEYS.HEALTH_ALERT_DELAY,
    category: 'reachability',
    label: 'Health alert delay',
    description:
      'How long a device must stay down, counted from the moment it is declared down, '
      + 'before an alert is raised. One alert per outage and one recovery notice when it '
      + 'answers again; a new outage of the same device is not announced sooner than the '
      + 'notification cooldown after the previous alert. 0 alerts as soon as it is declared down. '
      + 'A device that has never answered a check is shown as down but not announced. When more '
      + 'than 10 devices of a workspace are announced within 10 minutes, the next ones are '
      + 'grouped into a single alert.',
    type: 'number',
    unit: 'seconds',
    default: 300,
    min: 0,
    max: 86400,
  },
  {
    key: SETTINGS_KEYS.BACKUP_4G_ALERT_DELAY,
    category: 'reachability',
    label: '4G backup alert after',
    description:
      'How long the active default route of the router (read by the permanent check) may stay on its '
      + 'cellular interface, while the site has a fixed uplink, before one alert is raised. The alert '
      + 'names the SIM line linked to the router and its last known balance, and a notice is sent '
      + 'when the route returns to the fixed line. A bench-prepared router is not announced before '
      + 'it is qualified. 0 turns the alert off.',
    type: 'number',
    unit: 'minutes',
    default: 120,
    min: 0,
    max: 10080,
  },
  {
    key: SETTINGS_KEYS.OPERATOR_OUTAGE_MIN_STORES,
    category: 'reachability',
    label: 'Operator outage: stores',
    description:
      'When at least this many stores of the same fixed-line provider fall back to 4G or lose their '
      + 'fixed line within the operator outage window, ONE grouped alert « Panne opérateur probable » '
      + 'is raised instead of one per store; their individual 4G backup alerts are folded under it. '
      + 'Platform-wide: the grouping spans every workspace, so only the main workspace\'s value is used.',
    type: 'number',
    unit: 'stores',
    default: 3,
    min: 2,
    max: 1000,
    workspaceOnly: true,
  },
  {
    key: SETTINGS_KEYS.OPERATOR_OUTAGE_WINDOW,
    category: 'reachability',
    label: 'Operator outage: window',
    description:
      'The time within which those stores must have lost their fixed line to be grouped. Stores of the '
      + 'same provider failing later join the open group. Platform-wide: only the main workspace\'s '
      + 'value is used.',
    type: 'number',
    unit: 'minutes',
    default: 10,
    min: 1,
    max: 1440,
    workspaceOnly: true,
  },
  {
    key: SETTINGS_KEYS.LINE_QUALITY_TARGET_1,
    category: 'reachability',
    label: 'Line quality: first ping target',
    description:
      'Outside opening hours, each store router pings this address through its fixed line (20 pings) to '
      + 'measure latency, loss and jitter. An IPv4 address that answers ping reliably; 0 = no first target.',
    type: 'number',
    unit: 'IPv4',
    // 8.8.8.8
    default: 134744072,
    min: 0,
    max: 4294967295,
  },
  {
    key: SETTINGS_KEYS.LINE_QUALITY_TARGET_2,
    category: 'reachability',
    label: 'Line quality: second ping target',
    description:
      'A second address pinged the same way, so one target having a bad night is not taken for the line. '
      + '0 = no second target; with both at 0 nothing is pinged.',
    type: 'number',
    unit: 'IPv4',
    // 1.1.1.1
    default: 16843009,
    min: 0,
    max: 4294967295,
  },
  {
    key: SETTINGS_KEYS.LINE_QUALITY_NIGHT_START,
    category: 'reachability',
    label: 'Line quality: night window opens at',
    description:
      'When the store\'s opening hours are not known, the nightly measurement runs between these two '
      + 'local hours (the site\'s time zone). With known hours it runs once the store has been closed for '
      + 'half an hour.',
    type: 'number',
    unit: 'h',
    default: 1,
    min: 0,
    max: 23,
  },
  {
    key: SETTINGS_KEYS.LINE_QUALITY_NIGHT_END,
    category: 'reachability',
    label: 'Line quality: night window closes at',
    description: 'The local hour the fallback night window ends (no measurement starts in its last half hour).',
    type: 'number',
    unit: 'h',
    default: 6,
    min: 0,
    max: 23,
  },
  {
    key: SETTINGS_KEYS.LINE_QUALITY_LOSS_PCT,
    category: 'reachability',
    label: 'Line quality: packet loss threshold',
    description:
      'A night whose packet loss through the fixed line reaches this value exceeds. 0 turns this rule off.',
    type: 'number',
    unit: '%',
    default: 5,
    min: 0,
    max: 100,
  },
  {
    key: SETTINGS_KEYS.LINE_QUALITY_LATENCY_MS,
    category: 'reachability',
    label: 'Line quality: latency threshold',
    description:
      'A night whose average round trip through the fixed line reaches this value exceeds. 0 turns this '
      + 'rule off.',
    type: 'number',
    unit: 'ms',
    default: 80,
    min: 0,
    max: 10000,
  },
  {
    key: SETTINGS_KEYS.LINE_QUALITY_RECONNECTIONS,
    category: 'reachability',
    label: 'Line quality: reconnections threshold',
    description:
      'A night exceeds when the day counted this many reconnections of the fixed line (WAN link-downs read '
      + 'on the router, or moves onto the 4G backup, whichever is higher). 0 turns this rule off.',
    type: 'number',
    unit: 'per day',
    default: 3,
    min: 0,
    max: 1000,
  },
  {
    key: SETTINGS_KEYS.LINE_QUALITY_RELATIVE_PCT,
    category: 'reachability',
    label: 'Line quality: above the line\'s own baseline by',
    description:
      'A night also exceeds when its latency, loss or reconnections are this much above the store\'s own '
      + 'median over its previous 14 nights (at least 5 measured nights, and a minimal gap: 10 ms, 3 points '
      + 'of loss, 2 reconnections). 0 keeps the absolute thresholds only.',
    type: 'number',
    unit: '%',
    default: 50,
    min: 0,
    max: 1000,
  },
  {
    key: SETTINGS_KEYS.LINE_QUALITY_NIGHTS,
    category: 'reachability',
    label: 'Line quality: consecutive nights for « degraded »',
    description:
      'A line is degraded after this many consecutive measured nights over a threshold, and to be watched '
      + 'after one. One grouped alert per workspace lists the degraded lines, and closes when they recover.',
    type: 'number',
    unit: 'nights',
    default: 2,
    min: 1,
    max: 14,
  },
  {
    key: SETTINGS_KEYS.SNMP_POLL_INTERVAL,
    category: 'snmp',
    label: 'SNMP poll interval',
    description:
      'How often interface counters are polled. A device whose SNMP target sets its own '
      + 'interval keeps it.',
    type: 'number',
    unit: 'seconds',
    // See the key's comment: the interval the poller ran on before this was read.
    default: 30,
    min: 10,
    max: 3600,
  },
  {
    key: SETTINGS_KEYS.SNMP_TIMEOUT,
    category: 'snmp',
    label: 'SNMP timeout',
    description:
      'Time before an SNMP request is considered lost. A device whose SNMP target sets its own '
      + 'timeout keeps it.',
    type: 'number',
    unit: 'ms',
    default: 2000,
    min: 500,
    max: 60000,
  },
  {
    key: SETTINGS_KEYS.SNMP_RETRIES,
    category: 'snmp',
    label: 'SNMP retries',
    description:
      'Retries per SNMP request before the poll is marked failed. A device whose SNMP target '
      + 'sets its own count keeps it.',
    type: 'number',
    unit: 'retries',
    default: 1,
    min: 0,
    max: 10,
  },
  {
    key: SETTINGS_KEYS.SNMP_AUTO_TARGET_CREDENTIAL,
    category: 'snmp',
    label: 'Automatic SNMP target credential',
    description:
      'Poll every confirmed device with this SNMP credential, without configuring one target '
      + 'per device. 0 disables automatic targets. Inheritable per group, so one customer can '
      + 'be polled with its own community.',
    type: 'number',
    unit: 'credential id',
    // 0, and not a working default: a community string is a shared secret, and
    // guessing one for a customer's fleet is not a default anybody may pick on
    // an operator's behalf. The fleet is polled once a human names it — once.
    default: 0,
    min: 0,
    max: 2147483647,
  },
  {
    key: SETTINGS_KEYS.BENCH_DEFAULT_GROUP,
    category: 'configuration',
    label: 'Default group for bench-prepared routers',
    description:
      'The group a router created at the bench is placed in, so that the notifications and '
      + 'settings bound to that group reach it from the start. 0 leaves it in no group. A router '
      + 'the bench prepares again keeps the group it already has.',
    type: 'number',
    unit: 'group id',
    // 0, i.e. what the bench did before: which group a customer's routers sit
    // in decides who receives their alerts, and that is not a default to guess.
    default: 0,
    min: 0,
    max: 2147483647,
    workspaceOnly: true,
  },
  {
    key: SETTINGS_KEYS.SNAPSHOT_INTERVAL,
    category: 'configuration',
    label: 'Snapshot interval',
    description: 'How often a device configuration is collected and normalized',
    type: 'number',
    unit: 'minutes',
    default: 1440,
    min: 5,
    max: 43200,
  },
  {
    key: SETTINGS_KEYS.DRIFT_INTERVAL,
    category: 'configuration',
    label: 'Drift check interval',
    description: 'How often the observed NCM is compared to the desired NCM',
    type: 'number',
    unit: 'minutes',
    default: 1440,
    min: 5,
    max: 43200,
  },
  {
    key: SETTINGS_KEYS.COMMIT_CONFIRM_TIMEOUT,
    category: 'change',
    label: 'Commit-confirm timeout',
    description:
      'How long the on-device dead-man waits before rolling back on its own. It must exceed the '
      + 'post-apply soak by the time needed to reconnect and disarm (about two and a half '
      + 'minutes): a change on a device where it does not is refused before anything is written.',
    type: 'number',
    unit: 'seconds',
    default: 600,
    min: 60,
    max: 3600,
  },
  {
    key: SETTINGS_KEYS.APPLY_SOAK_SECONDS,
    category: 'change',
    label: 'Post-apply soak',
    description:
      'Observation window after a successful apply before the dead-man is disarmed. Must stay '
      + 'about two and a half minutes shorter than the commit-confirm timeout.',
    type: 'number',
    unit: 'seconds',
    default: 300,
    min: 30,
    max: 3600,
  },
  {
    key: SETTINGS_KEYS.MAX_CONCURRENT_JOBS,
    category: 'change',
    label: 'Max concurrent change jobs',
    description:
      'Upper bound on change jobs one worker process runs at the same time. Platform-wide: the '
      + "change queue is shared by every workspace, so only the main workspace's value is used.",
    type: 'number',
    unit: 'jobs',
    // 4, the concurrency the queue ran at before this was read (it read
    // OBLIWAN_CHANGE_CONCURRENCY, default 4), not the 5 advertised here then.
    default: 4,
    min: 1,
    max: 100,
    workspaceOnly: true,
  },
  {
    key: SETTINGS_KEYS.CLOSED_HOURS_MAINTENANCE,
    category: 'change',
    label: 'Closed hours as the maintenance window',
    description:
      'For a site with no maintenance window of its own, let change jobs run only while its store is '
      + 'closed (per its opening hours). A site with an explicit window keeps it, and a site with no known '
      + 'hours is not constrained. It changes when pushes may run, so it is off by default.',
    type: 'number',
    unit: '',
    default: 0,
    min: 0,
    max: 1,
    choices: [
      { value: 0, label: 'Off' },
      { value: 1, label: 'On' },
    ],
  },
  {
    key: SETTINGS_KEYS.ACCESS_CHECK_NIGHTLY,
    category: 'change',
    label: 'Nightly verification of the management access',
    description:
      'Once a night, verify every active router of the workspace as the "Verify management access and '
      + 'compliance" button does: PPP session, API-SSL access with the pinned certificate, missing template '
      + 'fixes, last failed job. Read-only towards the routers. One alert per cause (access, compliance, '
      + 'duplicated PPP session) lists the routers concerned; offline routers are counted apart, not alerted.',
    type: 'number',
    unit: '',
    // ON: it writes nothing to any router, and a fleet nobody re-verifies is
    // one whose broken accesses are found the day a change is needed.
    default: 1,
    min: 0,
    max: 1,
    workspaceOnly: true,
    choices: [
      { value: 0, label: 'Off' },
      { value: 1, label: 'On' },
    ],
  },
  {
    key: SETTINGS_KEYS.ACCESS_CHECK_NIGHTLY_HOUR,
    category: 'change',
    label: 'Nightly verification hour',
    description:
      'The hour the nightly verification starts at (Europe/Paris time). A night missed by more than four '
      + 'hours (server down, a verification already running) is skipped.',
    type: 'number',
    unit: 'h',
    default: 3,
    min: 0,
    max: 23,
    workspaceOnly: true,
  },
  {
    key: SETTINGS_KEYS.ACCESS_CHECK_AUTO_REAPPLY,
    category: 'change',
    label: 'Re-apply automatically after the nightly verification',
    description:
      'Right after the nightly verification, queue the management access or template-fix jobs it found '
      + 'needed, exactly as the re-apply button would, with the same refusals, never on a router in '
      + 'shipping, never the template fixes on a router in learning mode, and never again on a router whose '
      + 'previous automatic re-apply failed for the same cause. Neither job arms a dead-man: turning this on '
      + 'confirms that degraded safety level in your name, and the jobs carry your confirmation.',
    type: 'number',
    unit: '',
    // OFF: it writes to customer routers with nobody watching.
    default: 0,
    min: 0,
    max: 1,
    workspaceOnly: true,
    choices: [
      { value: 0, label: 'Off' },
      { value: 1, label: 'On' },
    ],
  },
  {
    key: SETTINGS_KEYS.ACCESS_CHECK_AUTO_REAPPLY_CAP,
    category: 'change',
    label: 'Automatic re-apply cap',
    description: 'Routers the automatic re-apply queues a job on per night, at most. The others wait for the next night.',
    type: 'number',
    unit: 'routers',
    default: 50,
    min: 1,
    max: 2000,
    workspaceOnly: true,
  },
  {
    key: SETTINGS_KEYS.SIM_SYNC_INTERVAL,
    category: 'mobile',
    label: 'SIM sync interval',
    // PLATFORM-WIDE, and the description says so because the field appears in
    // every workspace's settings screen while the sweep reads only the master
    // workspace's value (`services/sim/index.ts`). Partner accounts have no
    // tenant, so there is one sweep for the whole installation — an operator
    // editing this in their own workspace and seeing nothing change would
    // reasonably conclude the setting is broken.
    description:
      'How often each partner account is polled for lines and remaining data. ' +
      'Platform-wide: partner accounts are not per-workspace, so only the main ' +
      "workspace's value is used.",
    type: 'number',
    unit: 'minutes',
    // Four hours. Data depletion is a phenomenon of days, and one sweep costs
    // one request PER LINE against a partner API with no published rate limit —
    // 300 lines every 15 minutes is 28 800 calls a day and a banned account,
    // which would present as a fleet that stopped being watched. The floor of
    // 30 minutes is there so a hurried operator cannot turn this into a spider.
    default: 240,
    min: 30,
    max: 1440,
  },
  {
    key: SETTINGS_KEYS.SIM_LOW_DATA_THRESHOLD,
    category: 'mobile',
    label: 'Low data threshold',
    description: 'Default remaining data below which a line is reported low (per-line override available)',
    type: 'number',
    unit: 'MB',
    default: 1024,
    min: 0,
    max: 10_000_000,
  },
  {
    key: SETTINGS_KEYS.SIM_LOW_DATA_PERCENT,
    category: 'mobile',
    label: 'Low data (% of envelope used)',
    description: 'Share of each zone data envelope used at or above which the zone is reported low. Zones whose envelope is unknown fall back to the MB threshold',
    type: 'number',
    unit: '%',
    default: 80,
    min: 1,
    max: 100,
  },
  {
    key: SETTINGS_KEYS.SIM_ALERT_REMIND_HOURS,
    category: 'mobile',
    label: 'Low data reminder',
    description: 'How long before a line that is still low is announced again',
    type: 'number',
    unit: 'hours',
    default: 24,
    min: 1,
    max: 720,
  },
  {
    key: SETTINGS_KEYS.TIMESERIES_RETENTION_DAYS,
    category: 'retention',
    label: 'Time-series retention',
    description:
      'How long the 5-minute interface and device rollups are kept (the tier graphs over weeks '
      + 'and the billing 95th percentile read). Raw samples are kept 48 hours, 1-minute rollups '
      + '8 days and hourly rollups 2 years whatever this says. Platform-wide: only the main '
      + "workspace's value is used. Applied within the hour, a week of data at a time.",
    type: 'number',
    unit: 'days',
    // 90: the retention the 5-minute tier already had (series_partition_policy,
    // migration 006). Wiring the setting changes nothing until somebody edits it.
    default: 90,
    min: 1,
    max: 3650,
    workspaceOnly: true,
  },
  {
    key: SETTINGS_KEYS.CONFIG_RETENTION_DAYS,
    category: 'retention',
    label: 'Configuration retention',
    description:
      'How long a configuration snapshot that is no longer current is kept after it was last '
      + 'observed. The current configuration of a device is always kept, and so is any snapshot '
      + 'a change plan, an intervention or a drift run with findings refers to.',
    type: 'number',
    unit: 'days',
    default: 365,
    min: 1,
    max: 3650,
  },
  {
    key: SETTINGS_KEYS.AUDIT_RETENTION_DAYS,
    category: 'retention',
    label: 'Audit retention',
    description:
      'How long audit log and command audit entries are kept. Cannot be less than 400 days: '
      + 'younger entries are protected by the database itself.',
    type: 'number',
    unit: 'days',
    default: 730,
    // 400, not 30: migrations 009 and 019 refuse to delete an audit or
    // command-audit row younger than 400 days, so a shorter value could only
    // be shown, never applied. A stored value below it is clamped on read.
    min: 400,
    max: 3650,
    workspaceOnly: true,
  },
  {
    key: SETTINGS_KEYS.EVENT_HISTORY_RETENTION_DAYS,
    category: 'retention',
    label: 'Event history retention',
    description:
      'How long event histories are kept: reachability verdicts, WAN path events, identity '
      + 'observations and events, intervention lifecycle events, SIM balance samples and sync '
      + 'runs, CWMP sessions. The latest entry a current state depends on, and any entry another '
      + "record refers to as evidence, are always kept. Platform-wide: only the main workspace's "
      + 'value is used.',
    type: 'number',
    unit: 'days',
    default: 365,
    min: 30,
    max: 3650,
    workspaceOnly: true,
  },
  {
    key: SETTINGS_KEYS.RUN_HISTORY_RETENTION_DAYS,
    category: 'retention',
    label: 'Run history retention',
    description:
      'How long finished run and job histories are kept: drift runs without findings, change job '
      + 'step traces, baseline mining runs, configuration renders, discoveries still pending and no '
      + 'longer seen. Running jobs, the latest run of each device and anything a plan, an '
      + "intervention or a finding refers to are always kept. Platform-wide: only the main "
      + "workspace's value is used.",
    type: 'number',
    unit: 'days',
    default: 180,
    min: 30,
    max: 3650,
    workspaceOnly: true,
  },
];

export const HARDCODED_DEFAULTS: Record<SettingsKey, number> = {
  [SETTINGS_KEYS.NOTIFICATION_COOLDOWN]: 300,
  // 0 = notify anyway: what happened before opening hours existed.
  [SETTINGS_KEYS.CLOSED_STORE_NOTIFY]: 0,
  // 0: see the definition — what presence did before the setting was read.
  [SETTINGS_KEYS.PRESENCE_GRACE_PERIOD]: 0,
  [SETTINGS_KEYS.DEVICE_TIMEOUT]: 15000,
  [SETTINGS_KEYS.HEALTH_CHECK_INTERVAL]: 60,
  [SETTINGS_KEYS.HEALTH_CHECK_RETRIES]: 3,
  [SETTINGS_KEYS.HEALTH_ALERT_DELAY]: 300,
  // 0 = off. Two hours: a failover that outlasts a maintenance window.
  [SETTINGS_KEYS.BACKUP_4G_ALERT_DELAY]: 120,
  [SETTINGS_KEYS.OPERATOR_OUTAGE_MIN_STORES]: 3,
  [SETTINGS_KEYS.OPERATOR_OUTAGE_WINDOW]: 10,
  // Line quality (migration 097): 8.8.8.8 and 1.1.1.1, the night 01:00-06:00.
  [SETTINGS_KEYS.LINE_QUALITY_TARGET_1]: 134744072,
  [SETTINGS_KEYS.LINE_QUALITY_TARGET_2]: 16843009,
  [SETTINGS_KEYS.LINE_QUALITY_NIGHT_START]: 1,
  [SETTINGS_KEYS.LINE_QUALITY_NIGHT_END]: 6,
  [SETTINGS_KEYS.LINE_QUALITY_LOSS_PCT]: 5,
  [SETTINGS_KEYS.LINE_QUALITY_LATENCY_MS]: 80,
  [SETTINGS_KEYS.LINE_QUALITY_RECONNECTIONS]: 3,
  [SETTINGS_KEYS.LINE_QUALITY_RELATIVE_PCT]: 50,
  [SETTINGS_KEYS.LINE_QUALITY_NIGHTS]: 2,
  // The poller's own numbers before these were read (see the keys' comment).
  [SETTINGS_KEYS.SNMP_POLL_INTERVAL]: 30,
  [SETTINGS_KEYS.SNMP_TIMEOUT]: 2000,
  [SETTINGS_KEYS.SNMP_RETRIES]: 1,
  // 0 = off. See the key's comment: a community string is not guessable on an
  // operator's behalf, so supervision waits for one human decision.
  [SETTINGS_KEYS.SNMP_AUTO_TARGET_CREDENTIAL]: 0,
  // 0 = no group: the bench's behaviour before the setting existed.
  [SETTINGS_KEYS.BENCH_DEFAULT_GROUP]: 0,
  [SETTINGS_KEYS.SNAPSHOT_INTERVAL]: 1440,
  [SETTINGS_KEYS.DRIFT_INTERVAL]: 1440,
  [SETTINGS_KEYS.COMMIT_CONFIRM_TIMEOUT]: 600,
  [SETTINGS_KEYS.APPLY_SOAK_SECONDS]: 300,
  [SETTINGS_KEYS.MAX_CONCURRENT_JOBS]: 4,
  // 0 = off: it changes when pushes may run, so nobody gets it by default.
  [SETTINGS_KEYS.CLOSED_HOURS_MAINTENANCE]: 0,
  // Read-only towards the routers: on. The automatic re-apply writes: off.
  [SETTINGS_KEYS.ACCESS_CHECK_NIGHTLY]: 1,
  [SETTINGS_KEYS.ACCESS_CHECK_NIGHTLY_HOUR]: 3,
  [SETTINGS_KEYS.ACCESS_CHECK_AUTO_REAPPLY]: 0,
  [SETTINGS_KEYS.ACCESS_CHECK_AUTO_REAPPLY_CAP]: 50,
  [SETTINGS_KEYS.SIM_SYNC_INTERVAL]: 240,
  [SETTINGS_KEYS.SIM_LOW_DATA_THRESHOLD]: 1024,
  [SETTINGS_KEYS.SIM_LOW_DATA_PERCENT]: 80,
  [SETTINGS_KEYS.SIM_ALERT_REMIND_HOURS]: 24,
  [SETTINGS_KEYS.TIMESERIES_RETENTION_DAYS]: 90,
  [SETTINGS_KEYS.CONFIG_RETENTION_DAYS]: 365,
  [SETTINGS_KEYS.AUDIT_RETENTION_DAYS]: 730,
  [SETTINGS_KEYS.EVENT_HISTORY_RETENTION_DAYS]: 365,
  [SETTINGS_KEYS.RUN_HISTORY_RETENTION_DAYS]: 180,
};

const DEFINITION_BY_KEY = new Map<string, SettingDefinition>(
  SETTINGS_DEFINITIONS.map((d) => [d.key, d]),
);

export function isSettingsKey(value: unknown): value is SettingsKey {
  return typeof value === 'string' && DEFINITION_BY_KEY.has(value);
}

export function getSettingDefinition(key: SettingsKey): SettingDefinition | undefined {
  return DEFINITION_BY_KEY.get(key);
}

/** Clamps a candidate value into the definition bounds; falls back to the default. */
export function clampSetting(key: SettingsKey, value: number): number {
  const def = DEFINITION_BY_KEY.get(key);
  if (!def) return value;
  if (!Number.isFinite(value)) return def.default;
  return Math.min(def.max, Math.max(def.min, value));
}

// ============================================================================
// Instance-level TEXT settings
// ============================================================================
//
// Everything above is NUMERIC and inherited global → tenant → group → device,
// and this file's header forbids a string in SETTINGS_DEFINITIONS without
// changing every consumer: `settings.service` refuses a non-number,
// `SettingField` renders a number input, and `HARDCODED_DEFAULTS` is
// `Record<SettingsKey, number>`. A fact about the INSTALLATION that is text and
// must be the same for every tenant is declared here instead, with its own
// default and validator, and stored ONCE in `app_config` under its key —
// instance-level by construction, since that table has no tenant column.
//
// One entry. It is written by PUT /api/allocation/instance-domain
// (requireRole('admin')) and read by the allocation service. No settings
// screen shows it yet.

export const INSTANCE_SETTINGS_KEYS = {
  /**
   * The installation's DNS-style suffix, e.g. "customers.example", spliced into
   * PPP logins by the allocation template placeholder `{instance.domain}`.
   * Empty means NOT SET: a login template that uses it is then refused, never
   * rendered without it.
   */
  INSTANCE_DOMAIN: 'instance_domain',
} as const;

export type InstanceSettingsKey =
  (typeof INSTANCE_SETTINGS_KEYS)[keyof typeof INSTANCE_SETTINGS_KEYS];

export interface InstanceSettingDefinition {
  key: InstanceSettingsKey;
  label: string;
  description: string;
  type: 'text';
  default: string;
  maxLength: number;
}

/**
 * Longest installation domain accepted: 62. A PPP login is capped at 64
 * characters (PPP_LOGIN_MAX in server/src/services/allocation/pppIdentity.ts,
 * which this file cannot import), and the shortest login that carries the
 * domain is one site character and a dot in front of it — so a longer domain
 * could never appear in any login at all. The server harness asserts the two
 * bounds stay in step. This is only the absolute ceiling: whether a domain
 * fits a given tenant's template (its literals, its tenant slug) is judged
 * against that template when either is saved.
 */
export const INSTANCE_DOMAIN_MAX_LENGTH = 62;

export const INSTANCE_SETTINGS_DEFINITIONS: InstanceSettingDefinition[] = [
  {
    key: INSTANCE_SETTINGS_KEYS.INSTANCE_DOMAIN,
    label: 'Installation domain',
    description:
      'DNS-style suffix used by PPP login templates through {instance.domain}, e.g. ' +
      'customers.example. Platform-wide: one value for every workspace.',
    type: 'text',
    // Empty, not a guess: a domain names the operator's own zone, and a made-up
    // one would be spliced into every new site's PPP login.
    default: '',
    maxLength: INSTANCE_DOMAIN_MAX_LENGTH,
  },
];

export const INSTANCE_HARDCODED_DEFAULTS: Record<InstanceSettingsKey, string> = {
  [INSTANCE_SETTINGS_KEYS.INSTANCE_DOMAIN]: '',
};

/**
 * Why `value` is not a usable installation domain, or null when it is. The
 * empty string is valid and means "not set". Labels of letters, digits and
 * inner hyphens, 1-63 characters each, separated by single dots; case is kept
 * as written. Shared so a form can say the same sentence the server says.
 */
export function instanceDomainError(value: string): string | null {
  const v = value.trim();
  if (v === '') return null;
  if (v.length > INSTANCE_DOMAIN_MAX_LENGTH) {
    return `the domain is longer than ${INSTANCE_DOMAIN_MAX_LENGTH} characters`;
  }
  for (const label of v.split('.')) {
    if (label === '') return 'the domain has an empty label (a leading, trailing or doubled dot)';
    if (label.length > 63) return `the label "${label}" is longer than 63 characters`;
    if (!/^[A-Za-z0-9-]+$/.test(label)) {
      return `the label "${label}" may only hold letters, digits and hyphens`;
    }
    if (label.startsWith('-') || label.endsWith('-')) {
      return `the label "${label}" starts or ends with a hyphen`;
    }
  }
  return null;
}
