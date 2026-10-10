import type { Knex } from 'knex';

/**
 * 071 — the `management_access` job creates ObliWAN's own account, and says
 * what it did about it.
 *
 * OPERATOR DECISION 2026-10-04 (binding): on a router in service that lacks
 * it, the management_access job (services/change/managementAccess.service.ts)
 * CREATES the `obliwan` group and user — the written exception to "no user
 * creation on in-service routers" — and ObliWAN then uses that account for its
 * API and SSH calls instead of the historical one the reconciliation attached
 * the router with. Six columns on `management_access_jobs`, no DEFAULT on
 * any of them (a row that predates this migration, or a job that never got
 * that far, says nothing rather than something false):
 *
 *   account_action       what the job did about `obliwan`:
 *                          in_use   ObliWAN already logs in as obliwan; the
 *                                   account was not touched;
 *                          created  this job added the user (and the group,
 *                                   when it was absent);
 *                          present  the user was already there, created by an
 *                                   earlier run, and the password ObliWAN
 *                                   holds for it opened a session; not touched;
 *                          refused  the job refused because of the account
 *                                   (a group `obliwan` with another policy, a
 *                                   user `obliwan` ObliWAN holds no working
 *                                   password for): nothing was written.
 *   account_detail       the sentence the device card shows beside it. Moves
 *                        with `account_action` (both or neither).
 *   account_secret_enc   the password generated for `obliwan`, encrypted by the
 *   account_key_version  vault (secretVault.service, key generation beside it;
 *                        both or neither). Written BEFORE the user is added on
 *                        the router — vault first, router second, so a crash
 *                        between the two never leaves the router holding a
 *                        password nobody has — and CLEARED, on every row of
 *                        the device, once the switch has landed: from then on
 *                        the password lives in `device_transports` only. A run
 *                        whose proof failed leaves it here, and the next run of
 *                        the job for that device REUSES it rather than
 *                        generating a second one: that is what makes a re-run
 *                        converge on a router that already holds the account.
 *   account_switched_at  when the device's `ssh` and `routeros_api` transports
 *                        were switched to `obliwan` — after a fresh login with
 *                        it succeeded over api-ssl AND over SSH. NULL with
 *                        `created`/`present` = the account exists and ObliWAN
 *                        does not use it yet (the card says so).
 *   account_secret_disclosed_at
 *                        when this run's API login carried the `obliwan`
 *                        password to a TLS endpoint whose certificate was NOT
 *                        the one expected (the router's SSH print, or the pin)
 *                        — a session that opened although the handshake should
 *                        have refused it before `/login`. That password is
 *                        DISCLOSED, not merely unproven: it is erased from
 *                        every row of the device in the same transaction (so
 *                        a disclosed row never holds one: CHECK), and the
 *                        next run refuses the account by name and asks for it
 *                        to be removed from the router, instead of reusing the
 *                        password and switching both channels to it. A later
 *                        row that creates or stages a password (the account
 *                        was removed, a run recreated it) supersedes it.
 *
 * WHY NOT `device_transports.secret_next_enc` (migration 031). That slot is
 * the candidate password of the row's OWN username: rotation.service promotes
 * it into `secret_enc` under the same username, `pendingRotations` lists it as
 * a rotation of that account, and `discardCandidate` erases it. A password
 * for ANOTHER account parked there — `obliwan` on a row whose username is
 * `admin` — would be listed as a pending rotation of `admin`, and discarding
 * it would destroy the only copy of a password the router now holds. 058
 * kept every credential out of this table; this pair is the one exception,
 * encrypted like the transports, and its lifetime is the job's: written by the
 * run that generated it, read by the next run on the same device, cleared
 * when the switch lands.
 *
 * The CHECKs are written without a regular expression (knex rewrites `?` inside
 * `raw()`, project convention): IN lists of literals and IS NULL tests only.
 */

const ACTIONS = ['in_use', 'created', 'present', 'refused'] as const;

const CHECKS: Array<[string, string]> = [
  ['account_action_chk', `account_action IS NULL OR account_action IN (${ACTIONS.map((a) => `'${a}'`).join(', ')})`],
  ['account_detail_chk', '(account_action IS NULL) = (account_detail IS NULL)'],
  ['account_secret_pair_chk', '(account_secret_enc IS NULL) = (account_key_version IS NULL)'],
  ['account_switched_chk', "account_switched_at IS NULL OR account_action IN ('created', 'present')"],
  [
    'account_disclosed_chk',
    'account_secret_disclosed_at IS NULL OR (account_secret_enc IS NULL AND account_switched_at IS NULL ' +
      "AND account_action IN ('created', 'present'))",
  ],
];

export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable('management_access_jobs', (t) => {
    t.string('account_action', 16).nullable();
    t.text('account_detail').nullable();
    t.text('account_secret_enc').nullable();
    t.integer('account_key_version').nullable();
    t.timestamp('account_switched_at', { useTz: true }).nullable();
    t.timestamp('account_secret_disclosed_at', { useTz: true }).nullable();
  });
  for (const [name, expr] of CHECKS) {
    await knex.schema.raw(`ALTER TABLE management_access_jobs ADD CONSTRAINT management_access_jobs_${name} CHECK (${expr})`);
  }
  // The next run's lookup: the newest row of the device still holding a
  // password that was never switched to.
  await knex.schema.raw(
    'CREATE INDEX management_access_jobs_account_pending_idx ON management_access_jobs (device_id, job_id DESC) ' +
      'WHERE account_secret_enc IS NOT NULL',
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.raw('DROP INDEX IF EXISTS management_access_jobs_account_pending_idx');
  for (const [name] of [...CHECKS].reverse()) {
    await knex.schema.raw(`ALTER TABLE management_access_jobs DROP CONSTRAINT IF EXISTS management_access_jobs_${name}`);
  }
  await knex.schema.alterTable('management_access_jobs', (t) => {
    t.dropColumn('account_secret_disclosed_at');
    t.dropColumn('account_switched_at');
    t.dropColumn('account_key_version');
    t.dropColumn('account_secret_enc');
    t.dropColumn('account_detail');
    t.dropColumn('account_action');
  });
}
