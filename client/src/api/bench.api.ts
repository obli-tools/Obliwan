import apiClient from './client';
import type { ApiResponse } from '@obliwan/shared';

/**
 * The bench tool — what this instance publishes for the preparation workstation.
 *
 * ┌─ THE ONLY UNAUTHENTICATED ENDPOINT THIS CLIENT CALLS ────────────────────┐
 * │ `/api/bench/*` sits outside `tenantRouter` and carries no session guard, │
 * │ because the installed tool polls `/version` on its own to decide whether │
 * │ to self-update, and a workstation holds no operator session. It is read- │
 * │ only and publishes a version, a size and a hash — nothing about the      │
 * │ fleet. The UI reads the same endpoint rather than a privileged twin, so  │
 * │ the screen and the tool can never disagree about what is published.      │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
export interface BenchRelease {
  /** `null` when no VERSION travelled with the artefact. */
  version: string | null;
  /**
   * Whether the file is actually there, which is NOT `version !== null`: the
   * instance can know a version and hold no artefact, and offering a download
   * in that state is how a preparer ends up on a 404 with nothing to do.
   */
  available: boolean;
  sha256: string | null;
  file: string;
}

export const benchApi = {
  async release(): Promise<BenchRelease> {
    const res = await apiClient.get<ApiResponse<BenchRelease>>('/bench/version');
    return res.data.data as BenchRelease;
  },

  /**
   * The download is a plain browser navigation, not an XHR: the response is a
   * 28 MB attachment with its own Content-Disposition, and pulling it through
   * axios would buffer the whole installer in memory to hand it straight back
   * to the browser. The URL is relative so nginx proxies it like the rest.
   */
  downloadUrl(file: string): string {
    return `/api/bench/download/${encodeURIComponent(file)}`;
  },
};
