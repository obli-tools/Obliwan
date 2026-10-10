import type { Knex } from 'knex';

/**
 * 086 — the router MODEL a miner cluster and an extrapolation proposal were
 * mined for.
 *
 * The extrapolator used to cluster a client's routers by configuration
 * STRUCTURE only, so a client with three hardware models could come out with
 * profiles mixing them, and nothing recorded which model a proposal was for.
 * A mining run partitioned by model (`BaselineParams.partitionBy = 'model'`)
 * now records the model key on each cluster, the proposal carries it, and the
 * approval can pin the template to it (`templates.model_pattern`).
 *
 * NULL means "the run did not partition by model" or "the model is unknown"
 * (the label then says 'Modèle inconnu'). No DEFAULT: a default would claim a
 * model nobody read. The CHECK refuses a blank string, which would otherwise
 * be a third spelling of "unknown" — written as a length test, not a regex
 * (and no `?` anywhere: knex rewrites it inside raw()).
 */
export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable('baseline_clusters', (t) => {
    t.string('model', 64).nullable();
  });
  await knex.schema.alterTable('extrapolation_proposals', (t) => {
    t.string('model', 64).nullable();
  });
  await knex.schema.raw(
    "ALTER TABLE baseline_clusters ADD CONSTRAINT baseline_clusters_model_chk CHECK (model IS NULL OR btrim(model) <> '')",
  );
  await knex.schema.raw(
    "ALTER TABLE extrapolation_proposals ADD CONSTRAINT extrapolation_proposals_model_chk CHECK (model IS NULL OR btrim(model) <> '')",
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.raw('ALTER TABLE extrapolation_proposals DROP CONSTRAINT IF EXISTS extrapolation_proposals_model_chk');
  await knex.schema.raw('ALTER TABLE baseline_clusters DROP CONSTRAINT IF EXISTS baseline_clusters_model_chk');
  await knex.schema.alterTable('extrapolation_proposals', (t) => {
    t.dropColumn('model');
  });
  await knex.schema.alterTable('baseline_clusters', (t) => {
    t.dropColumn('model');
  });
}
