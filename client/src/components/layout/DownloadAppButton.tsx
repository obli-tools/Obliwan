import { useEffect, useState } from 'react';
import { Download } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { benchApi, type BenchRelease } from '@/api/bench.api';
import { useAuthStore } from '@/store/authStore';

/**
 * "Download app" — the preparation-workstation installer, in the topbar.
 *
 * ┌─ NOTHING TO DOWNLOAD: HIDDEN FOR OPERATORS, EXPLAINED TO ADMINS ─────────┐
 * │ `/api/bench/version` answers `available` separately from `version`, and  │
 * │ the distinction is the whole point: an instance can know which version   │
 * │ exists and hold no artefact. The installer is built and signed on the    │
 * │ build host and reaches the server inside the image (the Dockerfile       │
 * │ copies `server/dist-bench`) or through the `BENCH_ARTEFACT_DIR`          │
 * │ override — so an image built before the bench was, or an override        │
 * │ naming a directory without the MSI, has nothing to serve. An enabled     │
 * │ button in that state is a 404 with a download icon on it.                │
 * │                                                                          │
 * │ So the empty case splits by who is looking. An operator gets nothing: an │
 * │ inert control is noise to someone who cannot act on it. A PLATFORM ADMIN │
 * │ gets it disabled, with the reason — they are the one person who can      │
 * │ publish the artefact, and hiding it from them turns a deployment gap     │
 * │ into "my button is missing", which is indistinguishable from a stale     │
 * │ client build. That is exactly what happened the first time.              │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * A plain <a download>, never an XHR: the response is a ~28 MB attachment with
 * its own `Content-Disposition`, and routing it through axios would buffer the
 * whole installer in memory only to hand it back to the browser.
 *
 * The check never raises: this sits in the topbar of every page, and a
 * version check must not surface an error on screens that have nothing to do
 * with it.
 *
 * ┌─ NO ANSWER IS NOT "NOTHING PUBLISHED" ───────────────────────────────────┐
 * │ The server answers `/version` with a 200 whenever it is up, whether or   │
 * │ not an artefact exists. So a request that FAILS (a restart during a      │
 * │ deploy, a 502 from nginx) or has not come back yet says nothing about    │
 * │ the installer — and drawing it as the admin's "No installer published"   │
 * │ told them the opposite of the truth, on every page load until the answer │
 * │ landed and for the whole session when it never did: the topbar lives in  │
 * │ the persistent layout, so a one-shot check never ran again.              │
 * │                                                                          │
 * │ `null` therefore means UNKNOWN and draws nothing, for anyone. A failed   │
 * │ check is retried with a backoff (5 s doubling to 5 min) until the server │
 * │ actually answers; the first real answer ends the loop.                   │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
const RETRY_FIRST_MS = 5_000;
const RETRY_MAX_MS = 5 * 60_000;

export function DownloadAppButton() {
  const { t } = useTranslation();
  const [release, setRelease] = useState<BenchRelease | null>(null);
  const isAdmin = useAuthStore((s) => s.isAdmin());

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let delay = RETRY_FIRST_MS;
    const check = () => {
      benchApi
        .release()
        .then((r) => {
          // A body without a boolean `available` is not an answer either.
          if (typeof r?.available !== 'boolean') throw new Error('malformed /bench/version');
          if (!cancelled) setRelease(r);
        })
        .catch(() => {
          if (cancelled) return;
          timer = setTimeout(check, delay);
          delay = Math.min(delay * 2, RETRY_MAX_MS);
        });
    };
    check();
    return () => {
      cancelled = true;
      if (timer !== undefined) clearTimeout(timer);
    };
  }, []);

  // ── WHO IS OWED AN EXPLANATION, AND WHO IS OWED SILENCE ──────────────────
  //
  // This returned `null` for everyone when nothing was published, on the
  // reasoning that a dead control is worse than no control. For an ordinary
  // operator that holds: they cannot publish an installer, so an inert button
  // is noise. For a PLATFORM ADMIN it is precisely backwards — they are the
  // one person who can fix the absence, and hiding the button tells them
  // nothing at all. The first thing it produced was "I don't see my button",
  // with no way to tell a missing artefact from a stale deployment.
  //
  // So: admins see it, disabled, saying why. Everyone else sees nothing. And
  // only once the server has SAID `available: false` — see the box above.
  if (release === null) return null;
  if (!release.available) {
    if (!isAdmin) return null;
    return (
      <span
        title={t('header.downloadAppMissing')}
        className="flex cursor-not-allowed items-center gap-1.5 rounded-md px-2 py-1 text-[13px] text-text-muted opacity-60"
      >
        <Download size={15} />
        <span className="hidden sm:inline">{t('header.downloadApp')}</span>
      </span>
    );
  }

  return (
    <a
      href={benchApi.downloadUrl(release.file)}
      download
      title={
        release.version
          ? t('header.downloadAppVersion', { version: release.version })
          : t('header.downloadApp')
      }
      className="flex items-center gap-1.5 rounded-md px-2 py-1 text-[13px] text-text-secondary transition-colors hover:bg-bg-hover hover:text-text-primary"
    >
      <Download size={15} />
      <span className="hidden sm:inline">{t('header.downloadApp')}</span>
    </a>
  );
}
